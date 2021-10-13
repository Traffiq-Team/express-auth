const jwt = require('jsonwebtoken')
const NodeCache = require('node-cache')
const bb = require('bluebird')
bb.promisifyAll(jwt)

const keyCache = new NodeCache({ stdTTL: 300, checkperiod: 300 })

function TraffiqAuth ({
  appName,
  publicKey,
  enforceIp,
  enforceUserAgent,
  preventTokenReuse,
  queueUrl
}) {
  if (publicKey == null) {
    throw new Error('Missing publicKey')
  }

  if (queueUrl == null) {
    throw new Error('Missing queueUrl')
  }

  return async (req, res, next) => {
    const { query } = req

    try {
      // Case 1: Missing token -> Queue
      const token = query?.traffiqToken
      if (token == null) {
        return res.redirect(queueUrl)
      }

      // Case 2: Has token
      const decoded = await jwt.verifyAsync(token, publicKey, { algorithms: ['RS256'] })
      if (decoded) {
        const isValid = validateRequest(req, decoded, { appName, token, enforceIp, enforceUserAgent, preventTokenReuse })

        // Case 2a: Token is valid -> Application
        if (isValid) {
          return next()
        }
      }

      return res.redirect(queueUrl)
    } catch (err) {
      // Case 2b: Token is invalid -> Queue
      // Case other: Some other error occured -> Queue
      console.error(err)
      return res.redirect(queueUrl)
    }
  }
}

function validateRequest (req, decoded, options) {
  const { appName: decodedAppName, ipAddress, userAgent } = decoded
  const { appName, enforceIp, enforceUserAgent, preventTokenReuse, token } = options
  const { ip } = req

  if (appName !== decodedAppName) {
    throw new Error(`Mismatched appName, ${appName} !=3 ${decodedAppName}`)
  }

  if (enforceIp && (ipAddress !== ip)) {
    throw new Error(`Mismatched IP, ${ipAddress} !=3 ${ip}`)
  }

  const requestUserAgent = req.get('User-Agent')
  if (enforceUserAgent && (userAgent !== requestUserAgent)) {
    throw new Error(`Mismatched user agent, ${userAgent} !== ${requestUserAgent}`)
  }

  if (preventTokenReuse) {
    if (keyCache.has(token)) {
      throw new Error('Reused token')
    }

    keyCache.set(token, false)
  }
}

module.exports = TraffiqAuth
