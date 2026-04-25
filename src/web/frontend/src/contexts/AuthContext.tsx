import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { authApi, type LoginResponse, type UserInfo } from '@/api/auth'
import { AUTH_EXPIRED_EVENT } from '@/api/client'

interface AuthState {
  token: string | null
  user: UserInfo | null
  mustChangePassword: boolean
  isAuthenticated: boolean
  isLoading: boolean
}

interface AuthContextType extends AuthState {
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  changePassword: (newPassword: string) => Promise<void>
}

const AuthContext = createContext<AuthContextType | null>(null)

const TOKEN_KEY = 'deepvuln_token'
const USER_KEY = 'deepvuln_user'

export function AuthProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate()

  const [state, setState] = useState<AuthState>({
    token: localStorage.getItem(TOKEN_KEY),
    user: JSON.parse(localStorage.getItem(USER_KEY) || 'null'),
    mustChangePassword: false,
    isAuthenticated: !!localStorage.getItem(TOKEN_KEY),
    isLoading: true,
  })

  // Listen for 401 expiry events dispatched by the API client so that
  // navigation happens through React Router instead of a full page reload.
  useEffect(() => {
    const handleExpired = () => {
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(USER_KEY)
      setState({ token: null, user: null, mustChangePassword: false, isAuthenticated: false, isLoading: false })
      navigate('/login', { replace: true })
    }
    window.addEventListener(AUTH_EXPIRED_EVENT, handleExpired)
    return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handleExpired)
  }, [navigate])

  // Verify token on mount
  useEffect(() => {
    const verify = async () => {
      const token = localStorage.getItem(TOKEN_KEY)
      if (!token) {
        setState({ token: null, user: null, mustChangePassword: false, isAuthenticated: false, isLoading: false })
        return
      }
      try {
        const user = await authApi.getMe()
        setState({
          token,
          user,
          mustChangePassword: user.must_change_password,
          isAuthenticated: true,
          isLoading: false,
        })
      } catch {
        // Token invalid
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(USER_KEY)
        setState({ token: null, user: null, mustChangePassword: false, isAuthenticated: false, isLoading: false })
      }
    }
    verify()
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const res: LoginResponse = await authApi.login(username, password)
    localStorage.setItem(TOKEN_KEY, res.access_token)
    const user: UserInfo = {
      id: res.user_id,
      username: res.username,
      must_change_password: res.must_change_password,
      is_active: true,
    }
    localStorage.setItem(USER_KEY, JSON.stringify(user))
    setState({
      token: res.access_token,
      user,
      mustChangePassword: res.must_change_password,
      isAuthenticated: true,
      isLoading: false,
    })
  }, [])

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    setState({ token: null, user: null, mustChangePassword: false, isAuthenticated: false, isLoading: false })
  }, [])

  const changePassword = useCallback(async (newPassword: string) => {
    const res = await authApi.changePassword(newPassword)
    localStorage.setItem(TOKEN_KEY, res.access_token)
    setState(prev => ({
      ...prev,
      token: res.access_token,
      mustChangePassword: false,
      user: prev.user ? { ...prev.user, must_change_password: false } : null,
    }))
    localStorage.setItem(USER_KEY, JSON.stringify(
      state.user ? { ...state.user, must_change_password: false } : { id: 0, username: '', must_change_password: false, is_active: true }
    ))
  }, [state.user])

  return (
    <AuthContext.Provider value={{ ...state, login, logout, changePassword }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
