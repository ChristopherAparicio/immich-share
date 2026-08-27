import http from 'node:http'

const upstreamPort = 3101
const ippPort = Number(process.env.IPP_PORT || 3102)
// Production IPP is reachable only through the adjacent TLS proxy. Exercise
// the same trusted one-hop scheme so Secure session cookies are emitted.
const tlsProxyHeaders = { 'X-Forwarded-Proto': 'https' }
const shareKey = 'test-share-key-1234'
const assets = [0, 1, 2].map(index => ({
  id: `00000000-0000-4000-8000-00000000000${index}`,
  type: 'IMAGE',
  isTrashed: false,
  originalFileName: `photo-${index}.jpg`,
  originalMimeType: 'image/jpeg'
}))

const upstream = http.createServer((request, response) => {
  if (request.url?.startsWith('/api/server/version')) {
    response.writeHead(200, { 'Content-Type': 'application/json' })
    response.end(JSON.stringify({ major: 2, minor: 0, patch: 0 }))
    return
  }
  if (request.url?.startsWith('/api/shared-links/me')) {
    response.writeHead(200, { 'Content-Type': 'application/json' })
    response.end(JSON.stringify({
      key: shareKey,
      type: 'INDIVIDUAL',
      allowDownload: true,
      showMetadata: false,
      assets
    }))
    return
  }
  if (/\/api\/assets\/[0-9a-f-]+\/original/.test(request.url || '')) {
    const body = Buffer.alloc(128 * 1024, 0x61)
    response.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': String(body.length),
      'Content-Disposition': 'attachment; filename="photo.jpg"'
    })
    response.end(body)
    return
  }
  response.writeHead(404)
  response.end()
})

function cookiesFrom (response) {
  const values = response.headers.getSetCookie?.() || []
  if (values.length) return values.map(value => value.split(';', 1)[0]).filter(Boolean)
  const value = (response.headers.get('set-cookie') || '').split(';', 1)[0]
  return value ? [value] : []
}

function mergeCookies (existing, response) {
  const jar = new Map()
  for (const pair of [...String(existing).split(';'), ...cookiesFrom(response)]) {
    const trimmed = pair.trim()
    const separator = trimmed.indexOf('=')
    if (separator > 0) jar.set(trimmed.slice(0, separator), trimmed.slice(separator + 1))
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join('; ')
}

function csrfFrom (cookie) {
  const pair = String(cookie).split(';').map(value => value.trim()).find(value => value.startsWith('ipp-csrf='))
  return pair ? decodeURIComponent(pair.slice('ipp-csrf='.length)) : ''
}

async function prepare (cookie = '') {
  if (!cookie) {
    const gallery = await fetch(`http://127.0.0.1:${ippPort}/share/${shareKey}`, {
      headers: tlsProxyHeaders
    })
    if (!gallery.ok) throw new Error(`gallery returned ${gallery.status}`)
    cookie = mergeCookies('', gallery)
  }
  const csrf = csrfFrom(cookie)
  if (!csrf) throw new Error('gallery did not issue a CSRF cookie')
  const response = await fetch(`http://127.0.0.1:${ippPort}/share/${shareKey}/download/prepare`, {
    method: 'POST',
    headers: {
      ...tlsProxyHeaders,
      'Content-Type': 'application/json',
      'X-IPP-CSRF-Token': csrf,
      ...(cookie ? { Cookie: cookie } : {})
    },
    body: '{}'
  })
  if (response.status !== 202) throw new Error(`prepare returned ${response.status}: ${await response.text()}`)
  return { job: await response.json(), cookie: mergeCookies(cookie, response) }
}

async function status (job, cookie) {
  const response = await fetch(`http://127.0.0.1:${ippPort}/share/${shareKey}/download/jobs/${job.id}`, {
    headers: { ...tlsProxyHeaders, Cookie: cookie },
    cache: 'no-store'
  })
  if (!response.ok) throw new Error(`status returned ${response.status}: ${await response.text()} (cookie=${cookie ? 'present' : 'missing'}, id=${job.id})`)
  return response.json()
}

async function waitFor (job, cookie, wanted, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs
  let current
  while (Date.now() < deadline) {
    current = await status(job, cookie)
    if (current.state === wanted) return current
    if (current.state === 'failed' || current.state === 'cancelled') {
      throw new Error(`job entered ${current.state}: ${current.message || ''}`)
    }
    await new Promise(resolve => setTimeout(resolve, 50))
  }
  throw new Error(`job did not reach ${wanted}; last state=${current?.state}`)
}

await new Promise(resolve => upstream.listen(upstreamPort, '127.0.0.1', resolve))
await import('/app/dist/index.js')
await new Promise(resolve => setTimeout(resolve, 150))

let exitCode = 0
try {
  const first = await prepare()
  if (!first.cookie) throw new Error('first visitor did not receive a queue-session cookie')
  const ready = await waitFor(first.job, first.cookie, 'ready')
  if (!Number.isSafeInteger(ready.sizeBytes) || ready.sizeBytes <= 0) throw new Error('ready job has no ZIP size')

  const sameVisitor = await fetch(`http://127.0.0.1:${ippPort}/share/${shareKey}/download/prepare`, {
    method: 'POST',
    headers: {
      ...tlsProxyHeaders,
      'Content-Type': 'application/json',
      Cookie: first.cookie,
      'X-IPP-CSRF-Token': csrfFrom(first.cookie)
    },
    body: JSON.stringify({ assets: assets.slice(0, 2).map(asset => asset.id) })
  })
  if (sameVisitor.status !== 429) {
    throw new Error(`same visitor created a second job: status=${sameVisitor.status}`)
  }

  const second = await prepare()
  if (second.job.state !== 'queued') throw new Error(`second visitor was not queued: ${second.job.state}`)
  if ('position' in second.job) throw new Error('queued status disclosed its exact position')

  const firstFile = await fetch(
    `http://127.0.0.1:${ippPort}/share/${shareKey}/download/jobs/${first.job.id}/file`,
    { headers: { ...tlsProxyHeaders, Cookie: first.cookie } }
  )
  const firstBody = Buffer.from(await firstFile.arrayBuffer())
  if (firstFile.status !== 200 || firstBody.subarray(0, 2).toString() !== 'PK') {
    throw new Error(`first ZIP failed: status=${firstFile.status} bytes=${firstBody.length}`)
  }
  if (firstFile.headers.get('content-length') !== String(firstBody.length)) {
    throw new Error('first ZIP has no exact Content-Length')
  }

  await waitFor(second.job, second.cookie, 'ready')
  const ranged = await fetch(
    `http://127.0.0.1:${ippPort}/share/${shareKey}/download/jobs/${second.job.id}/file`,
    { headers: { ...tlsProxyHeaders, Cookie: second.cookie, Range: 'bytes=100-199' } }
  )
  const rangeBody = Buffer.from(await ranged.arrayBuffer())
  if (ranged.status !== 206 || rangeBody.length !== 100) {
    throw new Error(`range resume failed: status=${ranged.status} bytes=${rangeBody.length}`)
  }

  const leave = await fetch(
    `http://127.0.0.1:${ippPort}/share/${shareKey}/download/jobs/${second.job.id}`,
    {
      method: 'DELETE',
      headers: {
        ...tlsProxyHeaders,
        Cookie: second.cookie,
        'X-IPP-CSRF-Token': csrfFrom(second.cookie)
      }
    }
  )
  if (leave.status !== 204) throw new Error(`leave queue returned ${leave.status}`)

  console.log(`IPP ZIP queue E2E passed: queued -> ready, bytes=${firstBody.length}, range=100`)
} catch (error) {
  exitCode = 1
  console.error(error)
} finally {
  await new Promise(resolve => upstream.close(resolve))
  process.exit(exitCode)
}
