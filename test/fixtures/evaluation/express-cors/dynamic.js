// 改编自 cors 官方动态配置示例；仅调整注释，代码不变。
var dynamicCorsOptions = function(req, callback) {
  var corsOptions;
  if (req.path.startsWith('/auth/connect/')) {

    corsOptions = {
      origin: 'http://mydomain.com',
      credentials: true
    };
  } else {

    corsOptions = { origin: '*' };
  }
  callback(null, corsOptions);
};

app.use(cors(dynamicCorsOptions));

app.get('/auth/connect/twitter', function (req, res) {
  res.send('Hello');
});

app.get('/public', function (req, res) {
  res.send('Hello');
});

app.listen(80, function () {
  console.log('web server listening on port 80')
})
