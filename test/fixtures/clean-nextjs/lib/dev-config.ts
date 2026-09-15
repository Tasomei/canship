// 示例域名和本地服务的连接串不应报告。

/** 本地开发数据库。 */
export const LOCAL_DB = 'postgresql://postgres:devpassword@localhost:5432/app_dev'

/** 文档中的示例连接。 */
export const DOC_EXAMPLE = 'mongodb://admin:hunter2@db.example.com:27017/mydb'

/** 容器编排服务名。 */
export const DOCKER_REDIS = 'redis://default:localdev@host.docker.internal:6379'
