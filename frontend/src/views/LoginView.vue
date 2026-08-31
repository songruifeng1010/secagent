<template>
  <div class="login-page">
    <!-- 背景安全网格 -->
    <div class="login-bg-grid" />
    <div class="login-bg-glow" />

    <!-- 登录卡片 -->
    <div class="login-card">
      <!-- Logo 区域 -->
      <div class="login-header">
        <div class="login-logo">
          <svg width="40" height="40" viewBox="0 0 40 40" fill="none">
            <rect width="40" height="40" rx="10" fill="#dc2626"/>
            <path d="M12 20L18 26L28 14" stroke="white" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <div class="login-title">SecAgentX</div>
        <div class="login-subtitle">AI 安全智能体 · 企业版</div>
      </div>

      <!-- 表单 -->
      <n-form ref="formRef" :model="form" :rules="rules" @submit.prevent="login">
        <div class="form-field">
          <div class="field-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/>
            </svg>
            <span>用户名</span>
          </div>
          <n-input
            v-model:value="form.username"
            placeholder="请输入管理员用户名"
            :disabled="loading"
            size="large"
            @keyup.enter="login"
          />
        </div>

        <div class="form-field">
          <div class="field-label">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span>密码</span>
          </div>
          <n-input
            v-model:value="form.password"
            type="password"
            placeholder="请输入密码"
            :disabled="loading"
            show-password-on="click"
            size="large"
            @keyup.enter="login"
          />
        </div>

        <!-- 错误提示 -->
        <transition name="fade">
          <div v-if="errorMsg" class="error-banner" :class="{ shake: errorMsg }">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <span>{{ errorMsg }}</span>
          </div>
        </transition>

        <n-button
          type="primary"
          block
          :loading="loading"
          :disabled="loading"
          attr-type="submit"
          size="large"
          class="login-btn"
        >
          <template #icon v-if="!loading">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>
            </svg>
          </template>
          {{ loading ? '验证中...' : '登 录' }}
        </n-button>
      </n-form>

      <div class="login-footer">
        <span>首次使用？默认用户名 admin</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useMessage } from 'naive-ui'
import { buildApiUrl, hasWebSession, markWebSession } from '../utils/http.js'

const router = useRouter()
const route = useRoute()
const message = useMessage()

const formRef = ref(null)
const loading = ref(false)
const errorMsg = ref('')

const form = reactive({
  username: 'admin',
  password: '',
})

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

onMounted(() => {
  if (hasWebSession()) {
    const redirect = route.query.redirect || '/dashboard'
    router.push(redirect)
  }
})

async function login() {
  errorMsg.value = ''
  try { await formRef.value?.validate() } catch { return }
  loading.value = true
  try {
    const resp = await fetch(buildApiUrl('/api/auth/web/login'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username: form.username, password: form.password }),
    })
    const data = await resp.json()
    if (!resp.ok) {
      const errCode = data?.error?.code || ''
      const errMsgText = data?.error?.message || '登录失败'
      if (errCode === 'AUTH_WRONG_CREDENTIALS') throw new Error('用户名或密码错误')
      if (errCode === 'AUTH_PASSWORD_NOT_SET') throw new Error('系统未配置管理员密码，请联系运维人员')
      throw new Error(errMsgText)
    }
    markWebSession(true)
    localStorage.setItem('secagentx_user', JSON.stringify(data.user || {}))
    message.success('登录成功')
    const redirect = route.query.redirect || '/dashboard'
    router.push(redirect)
  } catch (e) {
    errorMsg.value = e.message || '网络错误，请检查后端服务是否运行'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-primary);
  position: relative;
  overflow: hidden;
}

/* ─── 背景安全网格 ─── */
.login-bg-grid {
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px);
  background-size: 40px 40px;
  animation: grid-scroll 20s linear infinite;
  z-index: 0;
}

@keyframes grid-scroll {
  0% { transform: translate(0, 0); }
  100% { transform: translate(40px, 40px); }
}

.login-bg-glow {
  position: absolute;
  width: 600px;
  height: 600px;
  border-radius: 50%;
  background: radial-gradient(circle, rgba(220,38,38,0.08) 0%, transparent 70%);
  top: -200px;
  right: -200px;
  z-index: 0;
  animation: glow-drift 8s ease-in-out infinite alternate;
}

@keyframes glow-drift {
  0% { transform: translate(0, 0) scale(1); }
  100% { transform: translate(60px, 40px) scale(1.2); }
}

/* ─── 登录卡片 ─── */
.login-card {
  position: relative;
  z-index: 1;
  width: 400px;
  max-width: 90vw;
  background: var(--bg-card);
  border: 1px solid var(--border-primary);
  border-radius: var(--radius-lg);
  padding: 40px 36px 32px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  transition: box-shadow var(--transition-normal);
}

.login-card:focus-within {
  box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(220,38,38,0.15);
}

/* ─── Logo ─── */
.login-header {
  text-align: center;
  margin-bottom: 32px;
}

.login-logo {
  display: inline-flex;
  margin-bottom: 16px;
  animation: logo-float 3s ease-in-out infinite;
}

@keyframes logo-float {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-4px); }
}

.login-title {
  font-size: 24px;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: 2px;
  margin-bottom: 4px;
}

.login-subtitle {
  font-size: 13px;
  color: var(--text-muted);
}

/* ─── 表单字段 ─── */
.form-field {
  margin-bottom: 20px;
}

.field-label {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--text-tertiary);
  font-size: 12px;
  font-weight: 500;
  margin-bottom: 6px;
}

/* ─── 错误提示 ─── */
.error-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  background: var(--error-bg);
  border: 1px solid rgba(239,68,68,0.2);
  border-radius: var(--radius-sm);
  color: var(--error);
  font-size: 12px;
  margin-bottom: 16px;
}

.error-banner.shake {
  animation: shake 0.4s ease;
}

@keyframes shake {
  0%, 100% { transform: translateX(0); }
  20% { transform: translateX(-6px); }
  40% { transform: translateX(6px); }
  60% { transform: translateX(-4px); }
  80% { transform: translateX(4px); }
}

/* ─── 登录按钮 ─── */
.login-btn {
  --n-height: 42px;
  font-weight: 600;
  letter-spacing: 2px;
  border-radius: var(--radius-sm);
  transition: all var(--transition-fast);
}

.login-btn:not(:disabled):hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-glow-red);
}

/* ─── 底部 ─── */
.login-footer {
  text-align: center;
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--border-primary);
  font-size: 11px;
  color: var(--text-muted);
}
</style>
