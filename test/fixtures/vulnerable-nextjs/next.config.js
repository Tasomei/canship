// Test fixture: a wildcard together with credentials. The CORS specification
// forbids the pair, so browsers reject the response and the cross-origin calls
// this was meant to enable never work.
module.exports = {
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ]
  },
}
