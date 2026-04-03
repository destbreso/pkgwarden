import https from "node:https";
import http from "node:http";

const NPM_REGISTRY = "https://registry.npmjs.org";

export class RegistryClient {
  #registryUrl;

  constructor(registryUrl = NPM_REGISTRY) {
    this.#registryUrl = registryUrl.replace(/\/$/, "");
  }

  async getPackageInfo(name) {
    const url = `${this.#registryUrl}/${encodeURIComponent(name).replace("%40", "@")}`;
    return this.#fetch(url);
  }

  async getPackageInfoAbbreviated(name) {
    const url = `${this.#registryUrl}/${encodeURIComponent(name).replace("%40", "@")}`;
    return this.#fetch(url, {
      Accept: "application/vnd.npm.install-v1+json",
    });
  }

  async getPackageVersion(name, version = "latest") {
    const url = `${this.#registryUrl}/${encodeURIComponent(name).replace("%40", "@")}/${version}`;
    return this.#fetch(url);
  }

  async getPackageTarballUrl(name, version = "latest") {
    const info = await this.getPackageVersion(name, version);
    return info?.dist?.tarball || null;
  }

  async downloadTarball(url, { maxSize = 50 * 1024 * 1024 } = {}) {
    return new Promise((resolve, reject) => {
      const client = url.startsWith("https") ? https : http;
      client
        .get(url, (res) => {
          if (
            res.statusCode >= 300 &&
            res.statusCode < 400 &&
            res.headers.location
          ) {
            return this.downloadTarball(res.headers.location, { maxSize }).then(
              resolve,
              reject,
            );
          }

          // Check content-length before downloading
          const contentLength = parseInt(res.headers["content-length"], 10);
          if (contentLength && contentLength > maxSize) {
            res.destroy();
            return reject(
              new Error(
                `Tarball too large: ${(contentLength / 1024 / 1024).toFixed(1)}MB exceeds ${(maxSize / 1024 / 1024).toFixed(0)}MB limit`,
              ),
            );
          }

          let totalSize = 0;
          const chunks = [];
          res.on("data", (chunk) => {
            totalSize += chunk.length;
            if (totalSize > maxSize) {
              res.destroy();
              return reject(
                new Error(
                  `Tarball download exceeded ${(maxSize / 1024 / 1024).toFixed(0)}MB limit`,
                ),
              );
            }
            chunks.push(chunk);
          });
          res.on("end", () => resolve(Buffer.concat(chunks)));
          res.on("error", reject);
        })
        .on("error", reject);
    });
  }

  async getDownloadCount(name, period = "last-week") {
    const url = `https://api.npmjs.org/downloads/point/${period}/${name}`;
    try {
      const data = await this.#fetch(url);
      return data?.downloads || 0;
    } catch {
      return 0;
    }
  }

  async #fetch(url, headers = {}) {
    return new Promise((resolve, reject) => {
      const client = url.startsWith("https") ? https : http;
      client
        .get(
          url,
          {
            headers: { Accept: "application/json", ...headers },
          },
          (res) => {
            if (res.statusCode === 404) {
              return resolve(null);
            }

            let data = "";
            res.on("data", (chunk) => {
              data += chunk;
            });
            res.on("end", () => {
              try {
                resolve(JSON.parse(data));
              } catch {
                reject(new Error(`Failed to parse response from ${url}`));
              }
            });
            res.on("error", reject);
          },
        )
        .on("error", reject);
    });
  }
}
