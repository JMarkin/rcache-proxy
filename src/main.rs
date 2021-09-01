#[macro_use]
extern crate log;

use bytes::Bytes;
use evmap::{ReadHandle, WriteHandle};
use lazy_static::lazy_static;
use ntex::http::client::Client;
use ntex::http::header::HeaderValue;
use ntex::http::HeaderMap;
use ntex::rt::{spawn, time};
use ntex::web::{self, middleware, App, Error, HttpRequest, HttpResponse};
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::collections::BinaryHeap;
use std::env;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use url::Url;

const JSON: &str = "application/json";

lazy_static! {
    static ref APPL_JSON: HeaderValue = HeaderValue::from_static(JSON);
    static ref RUST_LOG: String = env::var("RUST_LOG").unwrap_or("info".to_string());
    static ref FORWARD_URL: String = env::var("FORWARD_URL").unwrap();
    static ref CACHE_TIMEOUT: String = env::var("CACHE_TIMEOUT").unwrap_or("30".to_string());
    static ref WORKERS: String = env::var("WORKERS").unwrap_or("1".to_string());
}

#[derive(Eq, Debug)]
struct CacheExpr {
    pub time: SystemTime,
    pub key: u64,
}

impl Ord for CacheExpr {
    fn cmp(&self, other: &Self) -> Ordering {
        other.time.cmp(&self.time)
    }
}

impl PartialOrd for CacheExpr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for CacheExpr {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

type CacheValue = Arc<(SystemTime, Bytes)>;

type Safe<T> = Arc<Mutex<T>>;

#[derive(Clone)]
struct Cache {
    reader: ReadHandle<u64, CacheValue>,
    writer: Safe<WriteHandle<u64, CacheValue>>,

    pub expired_keys: Safe<BinaryHeap<CacheExpr>>,
    timeout: Duration,
}

impl Cache {
    pub fn new() -> Self {
        let (reader, writer) = evmap::new();

        Cache {
            reader,
            writer: Arc::new(Mutex::new(writer)),
            expired_keys: Arc::new(Mutex::new(BinaryHeap::new())),
            timeout: Duration::new(CACHE_TIMEOUT.parse::<u64>().unwrap(), 0),
        }
    }

    fn clear(&self, key: u64) {
        info!("expire key {}", key);

        let mut w = self.writer.lock().unwrap();
        w.empty(key);
        w.refresh();
    }

    pub fn contains_get(&self, key: u64) -> Option<Vec<u8>> {
        if !self.reader.contains_key(&key) {
            return None;
        }

        let cache_value = self.reader.get_one(&key).unwrap().clone();

        if cache_value.0 < SystemTime::now() {
            self.clear(key);
            return None;
        }

        Some(cache_value.1.to_vec())
    }

    pub fn set(&self, key: u64, val: &Bytes) {
        let expire = SystemTime::now() + self.timeout;

        let mut writer = self.writer.lock().unwrap();
        writer.insert(key, Arc::new((expire, val.clone())));
        writer.refresh();

        self.expired_keys
            .lock()
            .unwrap()
            .push(CacheExpr { time: expire, key })
    }
}

async fn expire_keys(cache: Cache) {
    loop {
        loop {
            let value = cache.expired_keys.lock().unwrap().pop();

            if let Some(value) = value {
                debug!("find value {:?}", value);
                if value.time < SystemTime::now() {
                    info!("find expire key {}", value.key);
                    cache.clear(value.key);
                } else {
                    cache.expired_keys.lock().unwrap().push(value);
                    break;
                }
            } else {
                break;
            }
        }

        time::delay_for(Duration::from_millis(1000)).await;
    }
}

fn get_key(headers: &HeaderMap, path: &str, query: Option<&str>, body: &Bytes) -> u64 {
    let mut hash = DefaultHasher::new();

    body.hash(&mut hash);
    path.hash(&mut hash);
    query.hash(&mut hash);
    let auth_header = headers.get("Authorizaion");
    auth_header.hash(&mut hash);
    let auth_header = headers.get("X-Authorizaion");
    auth_header.hash(&mut hash);

    hash.finish()
}
async fn forward(
    req: HttpRequest,
    body: Bytes,
    url: web::types::Data<Url>,
    client: web::types::Data<Client>,
    cache: web::types::Data<Cache>,
) -> Result<HttpResponse, Error> {
    let mut new_url = url.get_ref().clone();
    let path = req.uri().path();
    let query = req.uri().query();
    new_url.set_path(path);
    new_url.set_query(query);

    let headers = req.headers().clone();

    let accept_json = headers.get("Accept") == Some(&APPL_JSON);

    let key = get_key(&headers, path, query, &body);

    //if accept json check cache

    if accept_json {
        info!("try find in cache {}", key);
        let value = cache.contains_get(key);
        if let Some(val) = value {
            info!("find in cache {}", key);

            return Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(val));
        }
    }

    // request
    let mut forwarded_req = client
        .request(req.method().clone(), new_url.as_str())
        .no_decompress();

    let req_headers = forwarded_req.headers_mut();

    for (key, value) in headers.into_iter() {
        req_headers.insert(key.clone(), value.clone());
    }

    let host = url.host_str().unwrap();

    let forwarded_req = forwarded_req.set_header("host", host);

    info!("Start forward {:?}", forwarded_req);
    let mut res = forwarded_req
        .send_body(body.clone())
        .await
        .map_err(Error::from)?;
    info!("Response {:?}", res);

    let mut client_resp = HttpResponse::build(res.status());
    // Remove `Connection` as per
    // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection#Directives
    for (header_name, header_value) in res.headers().iter().filter(|(h, _)| *h != "connection") {
        client_resp.header(header_name.clone(), header_value.clone());
    }

    // if json put to cache

    if accept_json {
        let resp_type_json = res.header("content-type") == Some(&APPL_JSON);

        if resp_type_json {
            info!("try add to cache {}", key);
            let body = res.body().await?;
            cache.set(key, &body.clone());
            info!("added to cache {}", key);
            return Ok(client_resp.body(body.to_vec()));
        }
    }

    Ok(client_resp.streaming(res))
}

#[ntex::main]
async fn main() -> std::io::Result<()> {
    env::set_var("RUST_LOG", &RUST_LOG.as_str());
    env_logger::init();
    let forward_url = Url::parse(&FORWARD_URL.as_str()).unwrap();

    let cache = Cache::new();

    spawn(expire_keys(cache.clone()));

    let workers: usize = WORKERS.parse::<usize>().unwrap();

    web::server(move || {
        App::new()
            .data(Client::new())
            .data(cache.clone())
            .data(forward_url.clone())
            .wrap(middleware::Logger::default())
            .default_service(web::route().to(forward))
    })
    .workers(workers)
    .bind(("0.0.0.0", 8000))?
    .stop_runtime()
    .run()
    .await
}
