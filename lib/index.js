var express = require('express');
var request = require('request');
var cors = require('cors');
var chalk = require('chalk');
var proxy = express();

var startProxy = function(port, proxyUrl, proxyPartial, credentials, origin) {
  proxy.use(cors({credentials: credentials, origin: origin}));
  proxy.options('*', cors({credentials: credentials, origin: origin}));

  // remove trailing slash
  var cleanProxyUrl = proxyUrl.replace(/\/$/, '');
  // remove all forward slashes
  var cleanProxyPartial = proxyPartial.replace(/\//g, '');

  // Add custom headers to disguise requests - with randomization
  const getUserAgent = () => {
    const userAgents = [
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0',
      'Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/96.0.4664.53 Mobile/15E148 Safari/604.1',
      'Mozilla/5.0 (iPad; CPU OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1'
    ];
    return userAgents[Math.floor(Math.random() * userAgents.length)];
  };

  // Create a cookie jar to maintain sessions
  const cookieJar = request.jar();

  // Track rate limits per endpoint
  const rateLimitTracker = {};
  const ipRotationPool = [];

  // Initialize IP rotation pool (for demonstration - in production you'd use real proxies)
  for (let i = 0; i < 20; i++) {
    ipRotationPool.push({
      ip: `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      lastUsed: 0,
      successRate: 1.0
    });
  }

  // Configure proxy middleware
  proxy.use('/' + cleanProxyPartial, function(req, res) {
    try {
      console.log(chalk.green('Request Proxied -> ' + req.url));
    } catch (e) {}

    // Preserve original request body and method
    const originalBody = [];
    req.on('data', (chunk) => {
      originalBody.push(chunk);
    });

    req.on('end', () => {
      const body = Buffer.concat(originalBody);
      
      // Get endpoint key for rate limiting
      const endpointKey = `${req.method}:${req.url.split('?')[0]}`;
      
      // Check if we're being rate limited on this endpoint
      if (rateLimitTracker[endpointKey] && rateLimitTracker[endpointKey].limited) {
        const waitTime = rateLimitTracker[endpointKey].resetTime - Date.now();
        if (waitTime > 0) {
          console.log(chalk.yellow(`Rate limited on ${endpointKey}, waiting ${waitTime}ms`));
          return setTimeout(() => {
            // Reset rate limit flag and retry
            rateLimitTracker[endpointKey].limited = false;
            req.pipe(request(requestOptions)).pipe(res);
          }, waitTime + 1000); // Add 1 second buffer
        }
      }
      
      // Select IP from rotation pool based on success rate and last used time
      const now = Date.now();
      ipRotationPool.sort((a, b) => {
        // Prioritize IPs with higher success rate and those used less recently
        const aScore = a.successRate * 10 - (now - a.lastUsed) / 60000;
        const bScore = b.successRate * 10 - (now - b.lastUsed) / 60000;
        return aScore - bScore;
      });
      
      const selectedIp = ipRotationPool[0];
      selectedIp.lastUsed = now;
      
      // Create request options with enhanced capabilities for Cloudflare bypass
      const requestOptions = {
        url: cleanProxyUrl + req.url,
        method: req.method,
        headers: {
          // Dynamic user agent to avoid detection patterns
          'User-Agent': getUserAgent(),
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Sec-Fetch-User': '?1',
          'Upgrade-Insecure-Requests': '1',
          'Connection': 'keep-alive',
          'DNT': '1',
          // Cloudflare specific headers
          'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96", "Google Chrome";v="96"',
          'sec-ch-ua-mobile': '?0',
          'sec-ch-ua-platform': '"Windows"',
          // Preserve important original headers
          'Referer': req.headers.referer || cleanProxyUrl,
          'Cookie': req.headers.cookie || '',
          'Content-Type': req.headers['content-type'] || '',
          'Content-Length': body.length || 0,
          // Add selected IP to X-Forwarded-For to avoid IP-based blocking
          'X-Forwarded-For': selectedIp.ip,
          'CF-Connecting-IP': selectedIp.ip
        },
        body: body.length ? body : undefined,
        timeout: 30000,
        followRedirect: true,
        followAllRedirects: true,
        maxRedirects: 10,
        strictSSL: false,
        gzip: true,
        encoding: null,
        time: true,
        pool: { maxSockets: 100 },
        jar: cookieJar // Use cookie jar to maintain session
      };

      // Remove empty headers
      Object.keys(requestOptions.headers).forEach(key => {
        if (!requestOptions.headers[key]) {
          delete requestOptions.headers[key];
        }
      });

      // Implement retry mechanism with circuit breaker pattern and rate limit awareness
      let retryCount = 0;
      const maxRetries = 3;
      let circuitBroken = false;
      const circuitResetTimeout = 60000; // 1 minute
      
      const makeRequest = () => {
        if (circuitBroken) {
          console.log(chalk.red('Circuit broken, request rejected'));
          return res.status(503).send('Service temporarily unavailable');
        }
        
        const reqStream = request(requestOptions);
        
        reqStream.on('error', (err) => {
          if (retryCount < maxRetries) {
            retryCount++;
            console.log(chalk.yellow(`Request failed, retrying (${retryCount}/${maxRetries}): ${err.message}`));
            // Exponential backoff with jitter
            const delay = 1000 * Math.pow(2, retryCount) * (0.5 + Math.random() * 0.5);
            setTimeout(makeRequest, delay);
          } else {
            console.log(chalk.red(`Request failed after ${maxRetries} retries: ${err.message}`));
            
            // Update IP success rate
            selectedIp.successRate = Math.max(0.1, selectedIp.successRate - 0.2);
            
            // Implement circuit breaker
            circuitBroken = true;
            setTimeout(() => {
              circuitBroken = false;
              console.log(chalk.green('Circuit reset, accepting requests again'));
            }, circuitResetTimeout);
            
            if (!res.headersSent) {
              res.status(500).send(`Proxy error: ${err.message}`);
            }
          }
        });
        
        reqStream.on('response', response => {
          // Handle Cloudflare challenges
          if (response.statusCode === 503 && response.headers.server && response.headers.server.includes('cloudflare')) {
            console.log(chalk.red('Cloudflare challenge detected'));
            
            // Update IP success rate
            selectedIp.successRate = Math.max(0.1, selectedIp.successRate - 0.1);
            
            // Could implement Cloudflare challenge solver here
            // For now, we'll just retry with a different IP after a delay
            if (retryCount < maxRetries) {
              retryCount++;
              // Select a different IP for the retry
              const differentIp = ipRotationPool.find(ip => ip.ip !== selectedIp.ip);
              if (differentIp) {
                requestOptions.headers['X-Forwarded-For'] = differentIp.ip;
                requestOptions.headers['CF-Connecting-IP'] = differentIp.ip;
              }
              
              const delay = 3000 + Math.random() * 2000; // 3-5 second delay
              console.log(chalk.yellow(`Retrying with different IP in ${Math.round(delay/1000)}s`));
              setTimeout(makeRequest, delay);
              return;
            }
          }
          
          // Handle rate limiting
          if (response.statusCode === 429) {
            console.log(chalk.red(`Rate limit detected for ${endpointKey}`));
            
            // Update IP success rate
            selectedIp.successRate = Math.max(0.1, selectedIp.successRate - 0.1);
            
            // Check for Retry-After header
            let retryAfter = 60000; // Default 1 minute
            if (response.headers['retry-after']) {
              const retryValue = parseInt(response.headers['retry-after'], 10);
              if (!isNaN(retryValue)) {
                retryAfter = retryValue * 1000; // Convert to ms
              }
            }
            
            // Track rate limit for this endpoint
            rateLimitTracker[endpointKey] = {
              limited: true,
              resetTime: Date.now() + retryAfter
            };
            
            console.log(chalk.yellow(`Rate limited. Will retry after ${retryAfter/1000}s`));
            
            // If we haven't exhausted retries, try again after the rate limit expires
            if (retryCount < maxRetries) {
              retryCount++;
              setTimeout(makeRequest, retryAfter + Math.random() * 5000);
              return;
            }
          }
          
          // Handle CORS headers
          const accessControlAllowOriginHeader = response.headers['access-control-allow-origin'];
          if(accessControlAllowOriginHeader && accessControlAllowOriginHeader !== origin) {
            console.log(chalk.blue('Override access-control-allow-origin header from proxified URL : ' + chalk.green(accessControlAllowOriginHeader) + '\n'));
            response.headers['access-control-allow-origin'] = origin;
          }
          
          // Add CORS headers if they don't exist
          if (!response.headers['access-control-allow-origin']) {
            response.headers['access-control-allow-origin'] = origin;
          }
          if (!response.headers['access-control-allow-methods']) {
            response.headers['access-control-allow-methods'] = 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD';
          }
          if (!response.headers['access-control-allow-headers']) {
            response.headers['access-control-allow-headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Auth-Token';
          }
          if (credentials && !response.headers['access-control-allow-credentials']) {
            response.headers['access-control-allow-credentials'] = 'true';
          }
          response.headers['access-control-max-age'] = '86400'; // 24 hours
          
          // Remove headers that might reveal it's a proxy
          delete response.headers['x-powered-by'];
          delete response.headers['server'];
          delete response.headers['via'];
          
          // On successful response, update IP success rate positively
          if (response.statusCode >= 200 && response.statusCode < 300) {
            selectedIp.successRate = Math.min(1.0, selectedIp.successRate + 0.05);
            
            // Reset rate limit for this endpoint if it was previously limited
            if (rateLimitTracker[endpointKey]) {
              rateLimitTracker[endpointKey].limited = false;
            }
          }
          
          // Reset retry counter on any non-error response
          retryCount = 0;
        });
        
        // Pipe the request body to the request
        if (body.length) {
          reqStream.write(body);
        }
        
        reqStream.pipe(res);
      };
      
      makeRequest();
    });
  });

  // Add health check endpoint
  proxy.get('/health', (req, res) => {
    res.status(200).json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      ipPool: ipRotationPool.map(ip => ({
        ip: ip.ip.replace(/\d+$/, 'xxx'), // Mask last octet for privacy
        successRate: ip.successRate.toFixed(2)
      }))
    });
  });

  // Add a catch-all error handler
  proxy.use((err, req, res, next) => {
    console.error(chalk.red('Proxy error:'), err);
    res.status(500).send('Proxy error occurred');
  });

  proxy.listen(port);

  // Welcome Message
  console.log(chalk.bgGreen.black.bold.underline('\n Proxy Active \n'));
  console.log(chalk.blue('Proxy Url: ' + chalk.green(cleanProxyUrl)));
  console.log(chalk.blue('Proxy Partial: ' + chalk.green(cleanProxyPartial)));
  console.log(chalk.blue('PORT: ' + chalk.green(port)));
  console.log(chalk.blue('Credentials: ' + chalk.green(credentials)));
  console.log(chalk.blue('Origin: ' + chalk.green(origin) + '\n'));
  console.log(
    chalk.cyan(
      'To start using the proxy simply replace the proxied part of your url with: ' +
        chalk.bold('http://localhost:' + port + '/' + cleanProxyPartial + '\n')
    )
  );
  console.log(chalk.yellow('Enhanced with advanced firewall bypass capabilities, retry logic, and circuit breaker\n'));
};

exports.startProxy = startProxy;
