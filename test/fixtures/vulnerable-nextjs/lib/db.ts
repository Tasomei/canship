// 模拟连接串保留真实格式主机名，避免占位检测误排除密码。

// 模拟含用户名和密码的连接串。
export const DATABASE_URL = 'postgresql://admin:sup3rS3cretPw@db.myapp.io:5432/production'

export function connect(): string {
  return DATABASE_URL
}
