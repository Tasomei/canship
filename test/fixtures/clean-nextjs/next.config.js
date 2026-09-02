// Test fixture: a realistic mixed CORS config, and the reason findings pair
// with the *nearest* origin declaration rather than any nearby one.
//
// A public route uses the wildcard. A few lines later a private route names one
// origin and allows credentials. Pairing the credentials with whichever origin
// happened to be within range would report the wildcard for a combination that
// never occurs on a single response.
module.exports = {
  async headers() {
    return [
      {
        source: '/api/public/:path*',
        headers: [{ key: 'Access-Control-Allow-Origin', value: '*' }],
      },
      {
        source: '/api/account/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: 'https://app.example.com' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ]
  },
}
