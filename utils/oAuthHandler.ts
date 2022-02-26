import axios from 'axios'
import CryptoJS from 'crypto-js'

import apiConfig from '../config/api.config'

// 只是伪装需要的令牌（包括但不限于客户端秘密，
// 访问令牌和刷新令牌），与以下两个函数一起使用
const AES_SECRET_KEY = 'onedrive-vercel-index'
export function obfuscateToken(token: string): string {
  // 使用 AES 加密令牌
  const encrypted = CryptoJS.AES.encrypt(token, AES_SECRET_KEY)
  return encrypted.toString()
}
export function revealObfuscatedToken(obfuscated: string): string {
  // 解密 SHA256 混淆令牌
  const decrypted = CryptoJS.AES.decrypt(obfuscated, AES_SECRET_KEY)
  return decrypted.toString(CryptoJS.enc.Utf8)
}

// 生成 Microsoft OAuth 2.0 授权 URL，用于请求授权码
export function generateAuthorisationUrl(): string {
  const { clientId, redirectUri, authApi, scope } = apiConfig
  const authUrl = authApi.replace('/token', '/authorize')

  // 为 OAuth2 构造 URL 参数
  const params = new URLSearchParams()
  params.append('client_id', clientId)
  params.append('redirect_uri', redirectUri)
  params.append('response_type', 'code')
  params.append('scope', scope)
  params.append('response_mode', 'query')
  console.error(`${authUrl}?${params.toString()}`);
  return `${authUrl}?${params.toString()}`
}

// 从 Microsoft OAuth 2.0 授权 URL 返回的代码是带有主机名的请求 URL
// http://localhost 和 URL 参数代码。 此函数从请求 URL 中提取代码
export function extractAuthCodeFromRedirected(url: string): string {
  // Return empty string if the url is not the defined redirect uri
  if (!url.startsWith(apiConfig.redirectUri)) {
    return ''
  }

  // New URL search parameter
  const params = new URLSearchParams(url.split('?')[1])
  return params.get('code') ?? ''
}

// 授权成功后，从 Microsoft OAuth 2.0 授权 URL 返回的代码
// will be used to request an access token. This function requests the access token with the authorisation code
// and returns the access token and refresh token on success.
export async function requestTokenWithAuthCode(
  code: string
): Promise<
  | { expiryTime: string; accessToken: string; refreshToken: string }
  | { error: string; errorDescription: string; errorUri: string }
> {
  const { clientId, redirectUri, authApi } = apiConfig
  const clientSecret = revealObfuscatedToken(apiConfig.obfuscatedClientSecret)

  // Construct URL parameters for OAuth2
  const params = new URLSearchParams()
  params.append('client_id', clientId)
  params.append('redirect_uri', redirectUri)
  params.append('client_secret', clientSecret)
  params.append('code', code)
  params.append('grant_type', 'authorization_code')

  // Request access token
  return axios
    .post(authApi, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    })
    .then(resp => {
      const { expires_in, access_token, refresh_token } = resp.data
      return { expiryTime: expires_in, accessToken: access_token, refreshToken: refresh_token }
    })
    .catch(err => {
      const { error, error_description, error_uri } = err.response.data
      return { error, errorDescription: error_description, errorUri: error_uri }
    })
}

// Verify the identity of the user with the access token and compare it with the userPrincipalName
// in the Microsoft Graph API. If the userPrincipalName matches, proceed with token storing.
export async function getAuthPersonInfo(accessToken: string) {
  const profileApi = apiConfig.driveApi.replace('/drive', '')
  return axios.get(profileApi, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  })
}

export async function sendTokenToServer(accessToken: string, refreshToken: string, expiryTime: string) {
  return await axios.post(
    '/api',
    {
      obfuscatedAccessToken: obfuscateToken(accessToken),
      accessTokenExpiry: parseInt(expiryTime),
      obfuscatedRefreshToken: obfuscateToken(refreshToken),
    },
    {
      headers: {
        'Content-Type': 'application/json',
      },
    }
  )
}
