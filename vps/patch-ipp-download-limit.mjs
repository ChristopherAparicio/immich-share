import { readFileSync, writeFileSync } from 'node:fs'

const target = process.argv[2] || '/app/dist/stream/download.js'
let source = readFileSync(target, 'utf8')

function replaceOnce (label, before, after) {
  const first = source.indexOf(before)
  if (first === -1) throw new Error(`IPP patch marker absent: ${label}`)
  if (source.indexOf(before, first + before.length) !== -1) {
    throw new Error(`IPP patch marker non unique: ${label}`)
  }
  source = source.replace(before, after)
}

replaceOnce(
  'size-limit-error',
  "const STAGING_DIR_PREFIX = 'ipp-zip-';",
  `const STAGING_DIR_PREFIX = 'ipp-zip-';
const ZIP_CACHE_PREFIX = 'ipp-zip-cache-';
class ZipSizeLimitError extends Error {
    constructor(maxBytes) {
        super(\`ZIP exceeds configured limit of \${maxBytes} bytes\`);
        this.name = 'ZipSizeLimitError';
    }
}`
)

replaceOnce(
  'crypto-import',
  `const path_1 = require("path");`,
  `const path_1 = require("path");
const crypto_1 = tslib_1.__importDefault(require("crypto"));`
)

replaceOnce(
  'cache-aware-startup-sweep',
  `        const cutoff = Date.now() - maxAgeMs;
        const entries = yield fs_1.promises.readdir(root).catch(() => []);`,
  `        const cutoff = Date.now() - maxAgeMs;
        const cacheMaxAgeMs = Math.max(60, (0, access_1.getNumericConfigOption)('ipp.downloadZipCacheTtlSeconds', 1800)) * 1000;
        const cacheCutoff = Date.now() - cacheMaxAgeMs;
        const entries = yield fs_1.promises.readdir(root).catch(() => []);`
)

replaceOnce(
  'cache-aware-startup-sweep-age',
  `            if (!stat || stat.mtimeMs >= cutoff)
                continue;
            yield fs_1.promises.rm(path, { recursive: true, force: true }).catch(e => {`,
  `            if (!stat)
                continue;
            if (name.startsWith(ZIP_CACHE_PREFIX) && stat.mtimeMs >= cacheCutoff) {
                scheduleZipCacheDeletion(path, Math.max(1, stat.mtimeMs + cacheMaxAgeMs - Date.now()));
                continue;
            }
            if (!name.startsWith(ZIP_CACHE_PREFIX) && stat.mtimeMs >= cutoff)
                continue;
            yield fs_1.promises.rm(path, { recursive: true, force: true }).catch(e => {`
)

replaceOnce(
  'preflight-free-space',
  `        res.setHeader('Content-Type', 'application/zip');
        let filename = ((0, sanitize_1.sanitize)((0, share_1.title)(share)) || 'photos') + '.zip';
        filename = encodeURI(filename);
        res.setHeader('Content-Disposition', \`attachment; filename*=UTF-8''\${filename}\`);
        // Hint to intermediate proxies (Nginx, etc.) not to buffer this response.
        res.setHeader('X-Accel-Buffering', 'no');`,
  `        const maxBytes = Math.max(1, (0, access_1.getNumericConfigOption)('ipp.maxDownloadZipBytes', 2147483648));
        const minFreeBytes = Math.max(0, (0, access_1.getNumericConfigOption)('ipp.minDownloadZipFreeBytes', 5368709120));
        const cacheTtlMs = Math.max(60, (0, access_1.getNumericConfigOption)('ipp.downloadZipCacheTtlSeconds', 1800)) * 1000;
        let filename = ((0, sanitize_1.sanitize)((0, share_1.title)(share)) || 'photos') + '.zip';
        filename = encodeURI(filename);
        const cachePath = zipCachePath(share, assets);
        const cached = yield validCachedZip(cachePath, cacheTtlMs);
        if (cached) {
            scheduleZipCacheDeletion(cachePath, Math.max(1, cached.mtimeMs + cacheTtlMs - Date.now()));
            const completed = yield serveZipFile(res, cachePath, filename, cached);
            if (!completed)
                (0, log_1.log)(\`Cached zip download for share \${share.key} cancelled by client\`);
            return;
        }
        yield fs_1.promises.rm(cachePath, { force: true }).catch(() => { });
        const disk = yield fs_1.promises.statfs((0, os_1.tmpdir)());
        const availableBytes = Number(disk.bavail) * Number(disk.bsize);
        // Worst case while building: staged originals + final STORE archive.
        if (availableBytes < (2 * maxBytes) + minFreeBytes) {
            res.status(507).type('text/plain').send('Insufficient staging space for ZIP download');
            return;
        }`
)

replaceOnce(
  'staging-options',
  `            concurrency: Math.max(1, (0, access_1.getNumericConfigOption)('ipp.downloadFromImmichConcurrencyLimit', 20)),
            maxAttempts: 3,`,
  `            concurrency: Math.max(1, (0, access_1.getNumericConfigOption)('ipp.downloadFromImmichConcurrencyLimit', 20)),
            maxBytes,
            byteCounter: { value: 0 },
            cachePath,
            partialPath: cachePath + '.part-' + process.pid + '-' + crypto_1.default.randomUUID(),
            maxAttempts: 3,`
)

replaceOnce(
  'delay-response-stream',
  `        archive.pipe(res);`,
  `        // Do not expose response headers or ZIP bytes until staging and
        // aggregate-size validation have both completed.`
)

replaceOnce(
  'cache-build-close-tracking',
  `        let clientGone = false;
        let resolveClosed;
        const resClosed = new Promise(resolve => { resolveClosed = resolve; });
        res.once('close', () => {
            if (res.writableFinished)
                return;
            clientGone = true;
            controller.abort();
            resolveClosed();
        });`,
  `        let clientGone = false;
        let cacheReady = false;
        res.once('close', () => {
            if (res.writableFinished)
                return;
            clientGone = true;
            controller.abort();
        });`
)

replaceOnce(
  'defer-archive-until-staged',
  `        let failure = null;
        for (const stage of stages) {
            const result = yield stage;
            if (result === null)
                break; // aborted by an earlier stage
            if ('failure' in result) {
                controller.abort();
                failure = result.failure;
                break;
            }
            // archive.file queues the entry; archiver lazily opens and reads it.
            archive.file(result.tempfile, { name: (0, filename_1.getFilename)(result.asset, result.endpoint.servedSize, result.servedMime) });
        }
        // After abort, wait for any in-flight stages to settle before we delete
        // the staging dir. stageOne never rejects (errors become failure objects),
        // so a plain Promise.all is safe.
        if (controller.signal.aborted)
            yield Promise.all(stages);
        return failure;`,
  `        let failure = null;
        const completed = [];
        for (const stage of stages) {
            const result = yield stage;
            if (result === null)
                break; // aborted by an earlier stage
            if ('failure' in result) {
                controller.abort();
                failure = result.failure;
                break;
            }
            completed.push(result);
        }
        // After abort, wait for any in-flight stages to settle before we delete
        // the staging dir. stageOne never rejects (errors become failure objects),
        // so a plain Promise.all is safe.
        if (controller.signal.aborted)
            yield Promise.all(stages);
        if (!failure) {
            for (const result of completed) {
                // Do not emit ZIP bytes until every asset is safely staged and
                // the aggregate size limit has been checked.
                archive.file(result.tempfile, { name: (0, filename_1.getFilename)(result.asset, result.endpoint.servedSize, result.servedMime) });
            }
        }
        return failure;`
)

replaceOnce(
  'friendly-size-error',
  `    (0, log_1.log)(\`Aborting zip download for share \${share.key}: failed to fetch asset \${failure.asset.id} from \${failure.url} (\${detail})\`);
    archive.abort();
    res.destroy();`,
  `    (0, log_1.log)(\`Aborting zip download for share \${share.key}: failed to fetch asset \${failure.asset.id} from \${failure.url} (\${detail})\`);
    archive.abort();
    if (failure.error instanceof ZipSizeLimitError && !res.headersSent) {
        res.removeHeader('Content-Disposition');
        res.status(413).type('text/plain').send('ZIP exceeds configured size limit');
        return;
    }
    res.destroy();`
)

replaceOnce(
  'start-response-after-staging',
  `            // finalize() resolves when archiver has finished writing the zip output,
            // which means every queued tempfile has been read. Safe to delete after.
            // Raced against client disconnect because finalize() never settles once
            // the response is destroyed. The inline rejection handler also stops a
            // late finalize failure becoming an unhandled rejection after a lost race.
            const finished = archive.finalize().then(() => 'done', () => 'error');
            const outcome = yield Promise.race([finished, resClosed.then(() => 'closed')]);
            if (outcome !== 'done') {
                if (outcome === 'closed')
                    (0, log_1.log)(\`Zip download for share \${share.key} cancelled by client\`);
                // 'error' was already logged by the archiver error listener
                archive.abort();
                res.destroy();
            }`,
  `            // Build an immutable archive first. This gives clients an exact
            // Content-Length and makes a later Range retry possible.
            const output = (0, fs_1.createWriteStream)(options.partialPath, { flags: 'wx', mode: 0o600 });
            archive.pipe(output);
            try {
                yield Promise.all([archive.finalize(), (0, promises_1.finished)(output)]);
                yield fs_1.promises.rename(options.partialPath, options.cachePath);
                cacheReady = true;
                scheduleZipCacheDeletion(options.cachePath, cacheTtlMs);
            }
            catch (e) {
                archive.abort();
                if (!clientGone && !res.headersSent)
                    res.status(503).type('text/plain').send('ZIP creation failed');
                return;
            }
            const cacheStat = yield fs_1.promises.stat(options.cachePath);
            if (clientGone) {
                (0, log_1.log)(\`Zip cache prepared for share \${share.key} after client disconnected\`);
                return;
            }
            const completed = yield serveZipFile(res, options.cachePath, filename, cacheStat);
            if (!completed)
                (0, log_1.log)(\`Zip download for share \${share.key} cancelled by client; cached archive retained\`);`
)

replaceOnce(
  'cleanup-partial-cache',
  `        finally {
            yield fs_1.promises.rm(options.stagingDir, { recursive: true, force: true }).catch(() => { });
        }`,
  `        finally {
            yield fs_1.promises.rm(options.stagingDir, { recursive: true, force: true }).catch(() => { });
            if (!cacheReady)
                yield fs_1.promises.rm(options.partialPath, { force: true }).catch(() => { });
        }`
)

replaceOnce(
  'resumable-cache-helpers',
  `/**
 * Kick off staging for every asset at once; the limiter caps how many run`,
  `function zipCachePath(share, assets) {
    const hash = crypto_1.default.createHash('sha256');
    hash.update(String(share.key));
    hash.update('\\0');
    for (const id of assets.map(asset => String(asset.id)).sort()) {
        hash.update(id);
        hash.update('\\0');
    }
    return (0, path_1.join)((0, os_1.tmpdir)(), ZIP_CACHE_PREFIX + hash.digest('hex') + '.zip');
}
function validCachedZip(path, maxAgeMs) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const stat = yield fs_1.promises.stat(path).catch(() => null);
        if (!stat || !stat.isFile() || stat.size <= 0 || stat.mtimeMs + maxAgeMs <= Date.now())
            return null;
        return stat;
    });
}
function scheduleZipCacheDeletion(path, delayMs) {
    const timer = setTimeout(() => {
        fs_1.promises.rm(path, { force: true }).catch(() => { });
    }, delayMs);
    timer.unref();
}
function serveZipFile(res, path, filename, stat) {
    return tslib_1.__awaiter(this, void 0, void 0, function* () {
        const size = stat.size;
        const rangeHeader = String((res.req && res.req.headers && res.req.headers.range) || '');
        let start = 0;
        let end = size - 1;
        let partial = false;
        if (rangeHeader) {
            const match = /^bytes=(\\d*)-(\\d*)$/.exec(rangeHeader.trim());
            if (!match || (!match[1] && !match[2])) {
                res.statusCode = 416;
                res.setHeader('Content-Range', \`bytes */\${size}\`);
                res.end();
                return true;
            }
            if (!match[1]) {
                const suffix = Number(match[2]);
                if (!Number.isSafeInteger(suffix) || suffix <= 0) {
                    res.statusCode = 416;
                    res.setHeader('Content-Range', \`bytes */\${size}\`);
                    res.end();
                    return true;
                }
                start = Math.max(0, size - suffix);
            }
            else {
                start = Number(match[1]);
                if (match[2])
                    end = Number(match[2]);
            }
            if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || start >= size || end < start) {
                res.statusCode = 416;
                res.setHeader('Content-Range', \`bytes */\${size}\`);
                res.end();
                return true;
            }
            end = Math.min(end, size - 1);
            partial = true;
        }
        res.statusCode = partial ? 206 : 200;
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', \`attachment; filename*=UTF-8''\${filename}\`);
        res.setHeader('Content-Length', String(end - start + 1));
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'private, no-store');
        res.setHeader('X-Accel-Buffering', 'no');
        if (partial)
            res.setHeader('Content-Range', \`bytes \${start}-\${end}/\${size}\`);
        if (res.req && res.req.method === 'HEAD') {
            res.end();
            return true;
        }
        try {
            yield (0, promises_1.pipeline)((0, fs_1.createReadStream)(path, { start, end }), res);
            return true;
        }
        catch (e) {
            if (res.destroyed || res.closed)
                return false;
            throw e;
        }
    });
}
/**
 * Kick off staging for every asset at once; the limiter caps how many run`
)

replaceOnce(
  'bounded-stream-call',
  `        const streamed = yield streamBodyToTempFile(fetched.response, tempfile, options.idleTimeoutMs);`,
  `        const streamed = yield streamBodyToTempFile(fetched.response, tempfile, options.idleTimeoutMs, options.byteCounter, options.maxBytes);`
)

replaceOnce(
  'bounded-stream-definition',
  `function streamBodyToTempFile(response, tempfile, idleMs) {`,
  `function streamBodyToTempFile(response, tempfile, idleMs, byteCounter, maxBytes) {`
)

replaceOnce(
  'bounded-stream-pipeline',
  `            yield (0, promises_1.pipeline)(body, (0, idleTimeoutStream_1.createIdleTimeoutStream)(idleMs), (0, fs_1.createWriteStream)(tempfile));`,
  `            const sizeGuard = new stream_1.Transform({
                transform(chunk, encoding, callback) {
                    byteCounter.value += chunk.length;
                    if (byteCounter.value > maxBytes) {
                        callback(new ZipSizeLimitError(maxBytes));
                        return;
                    }
                    callback(null, chunk);
                }
            });
            yield (0, promises_1.pipeline)(body, (0, idleTimeoutStream_1.createIdleTimeoutStream)(idleMs), sizeGuard, (0, fs_1.createWriteStream)(tempfile));`
)

writeFileSync(target, source)

const galleryTarget = process.argv[3] || '/app/dist/view/gallery.js'
let gallerySource = readFileSync(galleryTarget, 'utf8')
const galleryMarker = '"aria-label": "Download all", children:'
const galleryReplacement = '"aria-label": "Download all", download: "", children:'
const galleryMarkerIndex = gallerySource.indexOf(galleryMarker)
if (galleryMarkerIndex === -1) throw new Error('IPP patch marker absent: native-download-link')
if (gallerySource.indexOf(galleryMarker, galleryMarkerIndex + galleryMarker.length) !== -1) {
  throw new Error('IPP patch marker non unique: native-download-link')
}
gallerySource = gallerySource.replace(galleryMarker, galleryReplacement)
writeFileSync(galleryTarget, gallerySource)

console.log(`Patched IPP ZIP limits in ${target}`)
console.log(`Patched IPP native ZIP download link in ${galleryTarget}`)
