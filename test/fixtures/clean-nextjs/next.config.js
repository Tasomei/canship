// 混合公开与私有路由，验证来源按最近声明配对。
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
