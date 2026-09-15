// 客户端凭据选项不能被识别为服务端跨域策略。
import axios from 'axios'

export const api = axios.create({ baseURL: '/api', withCredentials: true })

/** 公开接口使用的独立跨域响应头。 */
export const PUBLIC_CORS = { 'Access-Control-Allow-Origin': '*' }

export function loadMe(): Promise<Response> {
  return fetch('/api/me', { credentials: 'include' })
}
