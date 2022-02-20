import { parseCookies, setCookie } from 'nookies'
import axios, { AxiosError } from 'axios'
import { signOut } from '../contexts/AuthContext'

let cookies = parseCookies()
let isRefreshing = false
let failedRequestsQueue = []

export const api = axios.create({
	baseURL: 'http://localhost:3333',
	headers: {
		Authorization: `Bearer ${cookies['nextauth.token']}`
	}
})

api.interceptors.response.use(
	(response) => {
		return response
	},
	(error: AxiosError) => {
		if (error.response?.status === 401) {
			// The strategy is to store failed requests in a queue
			// and retry them once the token is refreshed.
			// for that we need to know if we are already in a refresh process
			// if we aren't we can start one
			if (error.response.data.code === 'token.expired') {
				cookies = parseCookies()

				const { 'nextauth.refreshToken': refreshToken } = cookies
				const originalConfig = error.config

				if (!isRefreshing) {
					isRefreshing = true
					api
						.post('/refresh', {
							refreshToken
						})
						.then((response) => {
							const { token } = response.data
							setCookie(undefined, 'nextauth.token', token, {
								maxAge: 30 * 24 * 60 * 60,
								path: '/'
							})
							setCookie(
								undefined,
								'nextauth.refreshToken',
								response.data.refreshToken,
								{
									maxAge: 30 * 24 * 60 * 60,
									path: '/'
								}
							)
							api.defaults.headers.common.Authorization = `Bearer ${token}`
							failedRequestsQueue.forEach((request) => request.onSuccess(token))
							failedRequestsQueue = []
						})
						.catch((err) => {
							failedRequestsQueue.forEach((request) => request.onFailure(err))
							failedRequestsQueue = []
						})
						.finally(() => {
							isRefreshing = false
						})
				}

				return new Promise((resolve, reject) => {
					failedRequestsQueue.push({
						// It'll be executed when the token is refreshed
						onSuccess: (token: string) => {
							if (!originalConfig?.headers) {
								return
							}

							originalConfig.headers['Authorization'] = `Bearer ${token}`
							resolve(api(originalConfig))
						},

						// It'll be executed when the token refresh fails
						onFailure: (err: AxiosError) => {
							reject(err)
						}
					})
				})
			} else {
				signOut()
			}
		}

		return Promise.reject(error)
	}
)
