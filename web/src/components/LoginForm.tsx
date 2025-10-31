import { useState } from 'react';
import { api, type LoginResponse } from '../lib/api';
import { t, type Language } from '../i18n/translations';

interface LoginFormProps {
  language: Language;
  onSuccess: (session: LoginResponse) => void;
  onCancel?: () => void;
  onLanguageChange?: (language: Language) => void;
}

export function LoginForm({ language, onSuccess, onCancel, onLanguageChange }: LoginFormProps) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await api.login(username, password);
      onSuccess(response);
      setPassword('');
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('登录失败，请检查用户名和密码');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ background: '#0B0E11', color: '#EAECEF' }}>
      <div className="w-full max-w-md rounded-2xl p-6 sm:p-8 shadow-lg" style={{ background: '#1E2329', border: '1px solid #2B3139' }}>
        <div className="flex items-start justify-between gap-3 mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full flex items-center justify-center text-2xl" style={{ background: 'linear-gradient(135deg, #F0B90B 0%, #FCD535 100%)' }}>
              ⚡
            </div>
            <div>
              <h2 className="text-xl font-bold" style={{ color: '#EAECEF' }}>
                {t('appTitle', language)}
              </h2>
              <p className="text-xs mono" style={{ color: '#848E9C' }}>
                {t('subtitle', language)}
              </p>
            </div>
          </div>
          {onLanguageChange && (
            <div className="flex gap-1 rounded p-1" style={{ background: '#0B0E11' }}>
              <button
                type="button"
                onClick={() => onLanguageChange('zh')}
                className="px-2 py-1 rounded text-xs font-semibold transition-all"
                style={
                  language === 'zh'
                    ? { background: '#F0B90B', color: '#000' }
                    : { background: 'transparent', color: '#848E9C' }
                }
              >
                中文
              </button>
              <button
                type="button"
                onClick={() => onLanguageChange('en')}
                className="px-2 py-1 rounded text-xs font-semibold transition-all"
                style={
                  language === 'en'
                    ? { background: '#F0B90B', color: '#000' }
                    : { background: 'transparent', color: '#848E9C' }
                }
              >
                EN
              </button>
            </div>
          )}
        </div>

        <form className="space-y-5" onSubmit={handleSubmit}>
          <div className="space-y-2">
            <label className="text-sm font-medium" style={{ color: '#EAECEF' }}>
              用户名
            </label>
            <input
              type="text"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              className="w-full rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#F0B90B]"
              style={{ background: '#0B0E11', color: '#EAECEF', border: '1px solid #2B3139' }}
              required
            />
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium" style={{ color: '#EAECEF' }}>
              密码
            </label>
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              className="w-full rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#F0B90B]"
              style={{ background: '#0B0E11', color: '#EAECEF', border: '1px solid #2B3139' }}
              required
            />
          </div>

          {error && (
            <div className="text-sm px-4 py-2 rounded-md" style={{ background: 'rgba(246, 70, 93, 0.1)', color: '#F6465D' }}>
              {error}
            </div>
          )}

          <div className="flex items-center justify-between gap-3">
            {onCancel && (
              <button
                type="button"
                onClick={onCancel}
                className="flex-1 px-4 py-2 rounded-lg text-sm font-semibold transition-all"
                style={{ background: '#2B3139', color: '#848E9C' }}
                disabled={loading}
              >
                取消
              </button>
            )}
            <button
              type="submit"
              className="flex-1 px-4 py-2 rounded-lg text-sm font-semibold transition-all"
              style={{
                background: loading ? 'rgba(240, 185, 11, 0.4)' : '#F0B90B',
                color: '#000',
                cursor: loading ? 'not-allowed' : 'pointer',
              }}
              disabled={loading}
            >
              {loading ? '登录中…' : '登录'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default LoginForm;
