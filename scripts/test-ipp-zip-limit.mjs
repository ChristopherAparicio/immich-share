import http from 'node:http'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
require('/app/dist/config/loader.js').loadConfig()
const { downloadAssets } = require('/app/dist/stream/download.js')
const assetBytes = Number(process.env.TEST_ASSET_BYTES || 700000)
const expectedStatus = Number(process.env.TEST_EXPECT_STATUS || 413)
const upstreamPort = 3101
const proxyPort = 3102
let upstreamRequests = 0

const upstream = http.createServer((request, response) => {
  upstreamRequests++
  const body = Buffer.alloc(assetBytes, 0x61)
  response.writeHead(200, {
    'Content-Type': 'image/jpeg',
    'Content-Length': String(body.length),
    'Content-Disposition': 'attachment; filename="photo.jpg"'
  })
  response.end(body)
})

const assets = [0, 1].map(index => ({
  id: `00000000-0000-4000-8000-00000000000${index}`,
  type: 'IMAGE',
  originalFileName: `photo-${index}.jpg`,
  originalMimeType: 'image/jpeg',
  key: 'test-share-key'
}))
const share = {
  key: 'test-share-key',
  allowDownload: true,
  assets,
  description: 'ZIP limit regression test'
}

await new Promise(resolve => upstream.listen(upstreamPort, '127.0.0.1', resolve))
const proxy = http.createServer((request, response) => {
  // Minimal Express-compatible helpers used by the friendly 413 branch.
  response.status = code => { response.statusCode = code; return response }
  response.type = value => { response.setHeader('Content-Type', value); return response }
  response.send = value => { response.end(value); return response }
  return downloadAssets(response, share, assets)
})
await new Promise(resolve => proxy.listen(proxyPort, '127.0.0.1', resolve))

try {
  const response = await fetch(`http://127.0.0.1:${proxyPort}/download`)
  const body = Buffer.from(await response.arrayBuffer())
  if (response.status !== expectedStatus) {
    throw new Error(`expected HTTP ${expectedStatus}, received ${response.status}`)
  }
  if (expectedStatus === 200 && body.subarray(0, 2).toString() !== 'PK') {
    throw new Error('successful response is not a ZIP archive')
  }
  if (expectedStatus === 200 && response.headers.get('content-length') !== String(body.length)) {
    throw new Error('successful response has no exact Content-Length')
  }
  if (expectedStatus === 200 && response.headers.get('accept-ranges') !== 'bytes') {
    throw new Error('successful response does not advertise byte ranges')
  }
  if (expectedStatus === 413 && !body.toString().includes('size limit')) {
    throw new Error('size-limit response is not explicit')
  }
  if (expectedStatus === 200) {
    const requestsAfterBuild = upstreamRequests
    const range = await fetch(`http://127.0.0.1:${proxyPort}/download`, {
      headers: { Range: 'bytes=100-199' }
    })
    const rangeBody = Buffer.from(await range.arrayBuffer())
    if (range.status !== 206 || rangeBody.length !== 100) {
      throw new Error(`range retry failed: status=${range.status} bytes=${rangeBody.length}`)
    }
    if (range.headers.get('content-range') !== `bytes 100-199/${body.length}`) {
      throw new Error(`unexpected Content-Range: ${range.headers.get('content-range')}`)
    }
    if (upstreamRequests !== requestsAfterBuild) {
      throw new Error('range retry fetched assets from upstream instead of using cache')
    }
  }
  console.log(`IPP ZIP limit test passed: status=${response.status} bytes=${body.length}`)
} finally {
  await new Promise(resolve => proxy.close(resolve))
  await new Promise(resolve => upstream.close(resolve))
}
