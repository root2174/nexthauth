import Router from 'next/router'
import { createContext, useEffect, useState } from 'react'
import { api } from '../services/api'
import { setCookie, parseCookies, destroyCookie } from 'nookies'

type User = {
	email: string
	permissions: string[]
	roles: string[]
}

type SignInCredentials = {
	email: string
	password: string
}

type AuthContextData = {
	signIn(credentials: SignInCredentials): Promise<void>
	isAuthenticated: boolean
	user: User | undefined
}

type AuthProviderProps = {
	children: React.ReactNode
}

export const AuthContext = createContext({} as AuthContextData)

export function signOut() {
	destroyCookie(undefined, 'nextauth.token')
	destroyCookie(undefined, 'nextauth.refreshToken')

	Router.push('/')
}

export function AuthProvider({ children }: AuthProviderProps) {
	const [user, setUser] = useState<User>()
	const isAuthenticated = !!user

	useEffect(() => {
		async function fetchUserData() {
			try {
				const response = await api.get('/me')
				const { email, permissions, roles } = response.data
				setUser({
					email,
					permissions,
					roles
				})
			} catch (err) {
				signOut()
			}
		}
		const { 'nextauth.token': token } = parseCookies()

		if (token) {
			fetchUserData()
		}
	}, [])

	async function signIn({ email, password }: SignInCredentials) {
		try {
			const response = await api.post('/sessions', {
				email,
				password
			})

			const { token, refreshToken, permissions, roles } = response.data

			setCookie(undefined, 'nextauth.token', token, {
				maxAge: 60 * 60 * 24 * 30, // 30 days
				path: '/'
			})
			setCookie(undefined, 'nextauth.refreshToken', refreshToken, {
				maxAge: 60 * 60 * 24 * 30, // 30 days
				path: '/'
			})

			setUser({
				email,
				permissions,
				roles
			})
			api.defaults.headers.common['Authorization'] = `Bearer ${token}`
			Router.push('/dashboard')
		} catch (err) {
			console.log(err)
		}
	}

	return (
		<AuthContext.Provider value={{ signIn, isAuthenticated, user }}>
			{children}
		</AuthContext.Provider>
	)
}
