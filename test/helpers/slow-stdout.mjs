/** 延迟子进程输出，模拟异步管道；不改变写入内容。 */
const write = process.stdout.write.bind(process.stdout)
process.stdout.write = (...args) => {
  setTimeout(() => write(...args), 25)
  return true
}
