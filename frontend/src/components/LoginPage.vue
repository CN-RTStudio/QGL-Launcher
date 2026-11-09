<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  GetUsers, CreateGuestUser, CreateOfflineUser,
  LoginUser, SetCurrentUser, UserHasPassword,
  StartMicrosoftLogin, LoginYggdrasil, CreateExternalUser,
  GetYggdrasilServerInfo, DownloadAuthlibInjector
} from '../../wailsjs/go/main/App.js'
import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime.js'

const props = defineProps({
  isFirstRun: Boolean
})

const emit = defineEmits(['login-success'])

const { t } = useI18n()

function cleanError(e) {
  return String(e).replace('Error: ', '')
}

// 模式: 'create-guest' | 'create-offline' | 'create-premium' | 'create-external' | 'login'
const mode = ref(props.isFirstRun ? 'create-guest' : 'login')

const username = ref('')
const password = ref('')
const confirmPassword = ref('')
const securityPassword = ref('')
const error = ref('')
const loading = ref(false)
const users = ref([])

// 外置登录相关
const extServerURL = ref('')
const extTemplate = ref('custom') // 'custom' | 'littleskin'
const extServerName = ref('')
const extEmail = ref('') // 外置登录用邮箱作为用户名

// 当前选中的用户（用于登录模式展示头像和用户名）
const selectedUser = ref(null)

// 正版登录相关
const msLoginStep = ref('') // 'device-code' | 'polling' | 'progress'
const msDeviceCode = ref('')
const msVerifyURL = ref('')
const msProgressMsg = ref('')

const isCreateMode = computed(() => mode.value.startsWith('create'))
const isGuestCreate = computed(() => mode.value === 'create-guest')
const isOfflineCreate = computed(() => mode.value === 'create-offline')
const isPremiumCreate = computed(() => mode.value === 'create-premium')
const isExternalCreate = computed(() => mode.value === 'create-external')

// 显示的头像字母
const avatarLetter = computed(() => {
  if (isCreateMode.value) {
    return username.value ? username.value.charAt(0).toUpperCase() : '?'
  }
  if (selectedUser.value) {
    return selectedUser.value.username.charAt(0).toUpperCase()
  }
  return '?'
})

// 显示的用户名
const displayName = computed(() => {
  if (isCreateMode.value) {
    return username.value || t('login.newUser')
  }
  if (selectedUser.value) {
    return selectedUser.value.username
  }
  return t('login.selectUser')
})

// 当前选中用户是否有密码
const selectedUserHasPassword = computed(() => {
  if (selectedUser.value) {
    return selectedUser.value.hasPassword
  }
  return false
})

onMounted(async () => {
  await loadUsers()

  EventsOn('msLoginSuccess', (mcUsername) => {
    loading.value = false
    msLoginStep.value = ''
    emit('login-success', {
      username: mcUsername, hasPassword: false, type: 'premium', isLocked: false
    })
  })

  EventsOn('msLoginError', (errMsg) => {
    loading.value = false
    msLoginStep.value = ''
    error.value = errMsg
  })

  EventsOn('msLoginProgress', (msg) => {
    msProgressMsg.value = msg
  })
})

onUnmounted(() => {
  EventsOff('msLoginSuccess')
  EventsOff('msLoginError')
  EventsOff('msLoginProgress')
})

async function loadUsers() {
  try {
    users.value = await GetUsers()
  } catch (e) {
    console.error('加载用户列表失败:', e)
    users.value = []
  }
}

function resetState(clearExt = false) {
  error.value = ''
  username.value = ''
  password.value = ''
  confirmPassword.value = ''
  securityPassword.value = ''
  msLoginStep.value = ''
  selectedUser.value = null
  if (clearExt) {
    extServerURL.value = ''
    extEmail.value = ''
    extServerName.value = ''
    extTemplate.value = 'custom'
  }
}

// 创建访客用户
async function handleCreateGuest() {
  error.value = ''
  if (!username.value.trim()) {
    error.value = t('login.enterUsername')
    return
  }
  if (username.value.trim().length < 2) {
    error.value = t('login.usernameMinLength')
    return
  }
  if (!securityPassword.value.trim()) {
    error.value = t('login.enterSecurityPassword')
    return
  }
  if (securityPassword.value.trim().length < 4) {
    error.value = t('login.securityPasswordMinLength')
    return
  }

  loading.value = true
  try {
    await CreateGuestUser(username.value.trim(), securityPassword.value.trim())
    await SetCurrentUser(username.value.trim())
    emit('login-success', {
      username: username.value.trim(), hasPassword: false, type: 'guest', isLocked: true
    })
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    loading.value = false
  }
}

// 创建离线用户
async function handleCreateOffline() {
  error.value = ''
  if (!username.value.trim()) {
    error.value = t('login.enterUsername')
    return
  }
  if (username.value.trim().length < 2) {
    error.value = t('login.usernameMinLength')
    return
  }
  if (password.value && password.value !== confirmPassword.value) {
    error.value = t('login.passwordMismatch')
    return
  }

  loading.value = true
  try {
    await CreateOfflineUser(username.value.trim(), password.value)
    await SetCurrentUser(username.value.trim())
    emit('login-success', {
      username: username.value.trim(), hasPassword: !!password.value, type: 'offline', isLocked: false
    })
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    loading.value = false
  }
}

// 正版用户登录
async function handlePremiumLogin() {
  error.value = ''
  loading.value = true
  msLoginStep.value = 'polling'
  msProgressMsg.value = t('login.gettingDeviceCode')

  try {
    const result = await StartMicrosoftLogin()
    const parts = result.split('|')
    msVerifyURL.value = parts[0] || ''
    msDeviceCode.value = parts[1] || ''
    msLoginStep.value = 'device-code'
    msProgressMsg.value = t('login.completeLoginInBrowser')
  } catch (e) {
    loading.value = false
    msLoginStep.value = ''
    error.value = cleanError(e)
  }
}

// 登录（已选中用户）
async function handleLogin() {
  error.value = ''
  if (!selectedUser.value) {
    error.value = t('login.selectUserFirst')
    return
  }

  const name = selectedUser.value.username
  const userType = selectedUser.value.type || 'offline'

  loading.value = true
  try {
    if (userType === 'guest') {
      await SetCurrentUser(name)
      emit('login-success', { username: name, hasPassword: false, type: 'guest', isLocked: true })
    } else if (userType === 'premium') {
      try {
        await LoginUser(name, '')
        emit('login-success', { username: name, hasPassword: false, type: 'premium', isLocked: false })
      } catch (e) {
        error.value = t('login.premiumTokenExpired')
      }
    } else {
      await LoginUser(name, password.value)
      const hasPwd = await UserHasPassword(name)
      emit('login-success', { username: name, hasPassword: hasPwd, type: 'offline', isLocked: false })
    }
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    loading.value = false
  }
}

function switchToCreateGuest() {
  mode.value = 'create-guest'
  resetState()
}

function switchToCreateOffline() {
  mode.value = 'create-offline'
  resetState()
}

function switchToCreatePremium() {
  mode.value = 'create-premium'
  resetState()
}

function switchToCreateExternal() {
  mode.value = 'create-external'
  resetState(true)
}

function switchToLogin() {
  mode.value = 'login'
  resetState()
}

// 外置登录模板切换
function handleExtTemplateChange(template) {
  extTemplate.value = template
  if (template === 'littleskin') {
    extServerURL.value = 'https://littleskin.cn/api/yggdrasil'
    extServerName.value = 'LittleSkin'
  } else {
    extServerURL.value = ''
    extServerName.value = ''
  }
}

// 外置登录 - 获取服务器名称
async function fetchExtServerName() {
  if (!extServerURL.value.trim()) return
  try {
    const info = await GetYggdrasilServerInfo(extServerURL.value.trim())
    if (info && info.meta && info.meta.serverName) {
      extServerName.value = info.meta.serverName
    }
  } catch (e) {
    console.error('获取外置登录服务器信息失败:', e)
  }
}

// 外置登录
async function handleExternalLogin() {
  error.value = ''
  if (!extServerURL.value.trim()) {
    error.value = t('login.enterServerURL')
    return
  }
  if (!extEmail.value.trim()) {
    error.value = t('login.enterEmail')
    return
  }
  if (!password.value) {
    error.value = t('login.enterPassword')
    return
  }

  loading.value = true
  try {
    const authData = await LoginYggdrasil(extServerURL.value.trim(), extEmail.value.trim(), password.value)
    await CreateExternalUser(authData.username, authData)
    await SetCurrentUser(authData.username)
    DownloadAuthlibInjector().catch((e) => {
      console.error('预下载 authlib-injector 失败:', e)
    })
    emit('login-success', {
      username: authData.username,
      hasPassword: false,
      type: 'external',
      isLocked: false,
      serverName: authData.serverName || extServerName.value,
    })
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    loading.value = false
  }
}

// 从右下角用户列表选择用户
function selectUser(user) {
  error.value = ''
  password.value = ''
  selectedUser.value = user
  mode.value = 'login'

  const userType = user.type || 'offline'

  if (userType === 'guest') {
    handleGuestQuickLogin(user.username)
  } else if (userType === 'premium') {
    handlePremiumQuickLogin(user.username)
  } else if (userType === 'external') {
    handleExternalQuickLogin(user.username)
  } else if (!user.hasPassword) {
    handleQuickLogin(user.username)
  }
}

async function handleGuestQuickLogin(name) {
  loading.value = true
  try {
    await SetCurrentUser(name)
    emit('login-success', { username: name, hasPassword: false, type: 'guest', isLocked: true })
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    loading.value = false
  }
}

async function handlePremiumQuickLogin(name) {
  loading.value = true
  try {
    await LoginUser(name, '')
    emit('login-success', { username: name, hasPassword: false, type: 'premium', isLocked: false })
  } catch (e) {
    error.value = t('login.premiumTokenExpiredReadd')
    selectedUser.value = null
  } finally {
    loading.value = false
  }
}

async function handleExternalQuickLogin(name) {
  loading.value = true
  try {
    await LoginUser(name, '')
    emit('login-success', { username: name, hasPassword: false, type: 'external', isLocked: false })
  } catch (e) {
    error.value = t('login.externalTokenExpiredReadd')
    selectedUser.value = null
  } finally {
    loading.value = false
  }
}

async function handleQuickLogin(name) {
  loading.value = true
  try {
    await SetCurrentUser(name)
    emit('login-success', { username: name, hasPassword: false, type: 'offline', isLocked: false })
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    loading.value = false
  }
}

function getUserTypeLabel(type) {
  if (type === 'guest') return t('login.guest')
  if (type === 'premium') return t('login.premium')
  if (type === 'external') return t('login.external')
  return t('login.offline')
}
</script>

<template>
  <div class="win11-login">
    <!-- 中央内容区域 -->
    <div class="win11-center">
      <div class="login-glass-container">
      <!-- ===== 登录模式 ===== -->
      <template v-if="!isCreateMode">
        <!-- 正版登录流程（设备代码） -->
        <template v-if="msLoginStep === 'device-code'">
          <div class="ms-login-box fade-in">
            <div class="ms-auto-hint">{{ t('login.autoOpenedBrowser') }}</div>
            <div class="ms-step-title">{{ t('login.completeLoginInBrowser') }}</div>
            <div class="ms-step-desc">{{ t('login.step1OpenUrl') }}</div>
            <div class="ms-url-box">{{ msVerifyURL }}</div>
            <div class="ms-step-desc">{{ t('login.step2EnterCode') }}</div>
            <div class="ms-code-box">{{ msDeviceCode }}</div>
            <div class="ms-progress">{{ msProgressMsg }}</div>
            <div class="ms-waiting">{{ t('login.waitingLogin') }}</div>
          </div>
        </template>
        <!-- 正版登录轮询中 -->
        <template v-else-if="msLoginStep === 'polling'">
          <div class="ms-login-box fade-in">
            <div class="win11-avatar">
              <svg class="spin" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--primary)" stroke-width="2.5" stroke-linecap="round"><path d="M12 2a10 10 0 0 1 10 10"/></svg>
            </div>
            <div class="ms-progress">{{ msProgressMsg }}</div>
            <div class="ms-waiting">{{ t('login.connectingMicrosoft') }}</div>
          </div>
        </template>
        <!-- 普通登录界面 -->
        <template v-else>
          <div class="win11-avatar" :class="selectedUser?.type || 'offline'">
            {{ avatarLetter }}
          </div>
          <div class="win11-username">{{ displayName }}</div>

          <!-- 有密码：显示密码输入框 -->
          <template v-if="selectedUser && selectedUserHasPassword">
            <div class="win11-input-row">
              <input
                v-model="password"
                type="password"
                class="win11-input"
                :placeholder="t('login.password')"
                @keyup.enter="handleLogin()"
                autofocus
              />
              <button class="win11-submit-btn" :disabled="loading" @click="handleLogin()">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
              </button>
            </div>
          </template>
          <!-- 无密码且已选中用户：直接登录按钮 -->
          <template v-else-if="selectedUser && !selectedUserHasPassword">
            <button class="win11-login-btn" :disabled="loading" @click="handleLogin()">
              {{ loading ? t('login.loggingIn') : t('login.login') }}
            </button>
          </template>
          <!-- 未选中用户：提示选择 -->
          <template v-else>
            <div class="win11-hint">{{ t('login.selectFromBottom') }}</div>
          </template>
        </template>
      </template>

      <!-- ===== 创建模式 ===== -->
      <template v-if="isCreateMode">
        <!-- 创建模式头像 -->
        <div class="win11-avatar create-mode">
          {{ avatarLetter }}
        </div>
        <div class="win11-username">{{ isGuestCreate ? t('login.createGuestUser') : (isOfflineCreate ? t('login.createOfflineUser') : (isPremiumCreate ? t('login.premiumLogin') : (isExternalCreate ? t('login.externalLogin') : t('login.newUser')))) }}</div>

        <!-- 类型选择标签 -->
        <div class="win11-type-tabs">
          <button
            class="win11-type-tab"
            :class="{ active: isGuestCreate }"
            @click="switchToCreateGuest"
          >{{ t('login.guest') }}</button>
          <button
            class="win11-type-tab"
            :class="{ active: isOfflineCreate }"
            @click="switchToCreateOffline"
          >{{ t('login.offline') }}</button>
          <button
            class="win11-type-tab"
            :class="{ active: isPremiumCreate }"
            @click="switchToCreatePremium"
          >{{ t('login.premium') }}</button>
          <button
            class="win11-type-tab"
            :class="{ active: isExternalCreate }"
            @click="switchToCreateExternal"
          >{{ t('login.external') }}</button>
        </div>

        <!-- 正版登录流程 -->
        <template v-if="isPremiumCreate">
          <template v-if="msLoginStep === 'device-code'">
            <div class="ms-login-box fade-in">
              <div class="ms-auto-hint">{{ t('login.autoOpenedBrowser') }}</div>
              <div class="ms-step-title">{{ t('login.completeLoginInBrowser') }}</div>
              <div class="ms-step-desc">{{ t('login.step1OpenUrl') }}</div>
              <div class="ms-url-box">{{ msVerifyURL }}</div>
              <div class="ms-step-desc">{{ t('login.step2EnterCode') }}</div>
              <div class="ms-code-box">{{ msDeviceCode }}</div>
              <div class="ms-progress">{{ msProgressMsg }}</div>
              <div class="ms-waiting">{{ t('login.waitingLogin') }}</div>
            </div>
          </template>
          <template v-else-if="msLoginStep === 'polling'">
            <div class="ms-login-box fade-in">
              <div class="ms-progress">{{ msProgressMsg }}</div>
              <div class="ms-waiting">{{ t('login.connectingMicrosoft') }}</div>
            </div>
          </template>
          <template v-else>
            <div class="premium-info">
              <div class="premium-desc">{{ t('login.useMicrosoftLogin') }}</div>
              <div class="premium-hint">{{ t('login.clickBelowToLogin') }}</div>
              <button class="win11-login-btn" :disabled="loading" @click="handlePremiumLogin()">
                {{ loading ? t('login.processing') : t('login.loginMicrosoft') }}
              </button>
            </div>
          </template>
        </template>

        <!-- 访客创建 -->
        <template v-if="isGuestCreate">
          <div class="win11-form">
            <input
              v-model="username"
              class="win11-input win11-input-block"
              :placeholder="t('login.username')"
              @keyup.enter="handleCreateGuest()"
            />
            <input
              v-model="securityPassword"
              type="password"
              class="win11-input win11-input-block"
              :placeholder="t('login.securityPasswordStar')"
              @keyup.enter="handleCreateGuest()"
            />
            <div class="win11-form-hint">{{ t('login.securityPasswordHint') }}</div>
            <button class="win11-login-btn" :disabled="loading" @click="handleCreateGuest()">
              {{ loading ? t('login.creating') : t('login.createGuestUser') }}
            </button>
          </div>
        </template>

        <!-- 离线创建 -->
        <template v-if="isOfflineCreate">
          <div class="win11-form">
            <input
              v-model="username"
              class="win11-input win11-input-block"
              :placeholder="t('login.username')"
              @keyup.enter="handleCreateOffline()"
            />
            <input
              v-model="password"
              type="password"
              class="win11-input win11-input-block"
              :placeholder="t('login.passwordOptional')"
              @keyup.enter="handleCreateOffline()"
            />
            <input
              v-model="confirmPassword"
              type="password"
              class="win11-input win11-input-block"
              :placeholder="t('login.confirmPassword')"
              @keyup.enter="handleCreateOffline()"
            />
            <button class="win11-login-btn" :disabled="loading" @click="handleCreateOffline()">
              {{ loading ? t('login.creating') : t('login.createOfflineUser') }}
            </button>
          </div>
        </template>

        <!-- 外置登录 -->
        <template v-if="isExternalCreate">
          <div class="win11-form">
            <!-- 模板选择 -->
            <div class="ext-template-row">
              <button
                class="ext-template-btn"
                :class="{ active: extTemplate === 'littleskin' }"
                @click="handleExtTemplateChange('littleskin')"
              >LittleSkin</button>
              <button
                class="ext-template-btn"
                :class="{ active: extTemplate === 'custom' }"
                @click="handleExtTemplateChange('custom')"
              >{{ t('login.customServer') }}</button>
            </div>
            <!-- 服务器地址 -->
            <input
              v-model="extServerURL"
              class="win11-input win11-input-block"
              :placeholder="t('login.serverURLPlaceholder')"
              :disabled="extTemplate === 'littleskin'"
              @blur="fetchExtServerName"
              @keyup.enter="fetchExtServerName"
            />
            <div v-if="extServerName" class="ext-server-name">{{ extServerName }}</div>
            <!-- 邮箱/用户名 -->
            <input
              v-model="extEmail"
              class="win11-input win11-input-block"
              :placeholder="t('login.emailOrUsername')"
              @keyup.enter="handleExternalLogin()"
            />
            <!-- 密码 -->
            <input
              v-model="password"
              type="password"
              class="win11-input win11-input-block"
              :placeholder="t('login.password')"
              @keyup.enter="handleExternalLogin()"
            />
            <button class="win11-login-btn" :disabled="loading" @click="handleExternalLogin()">
              {{ loading ? t('login.loggingIn') : t('login.externalLoginBtn') }}
            </button>
          </div>
        </template>
      </template>

      <!-- 错误信息 -->
        <div v-if="error" class="win11-error fade-in">{{ error }}</div>
      </div>
    </div>

    <!-- 左下角：用户列表 + 注册用户 -->
    <div class="win11-bottom-left">
      <div class="bottom-glass-container">
      <div class="win11-user-panel">
        <div
          v-for="user in users"
          :key="user.username"
          class="win11-user-chip"
          :class="{ active: selectedUser?.username === user.username }"
          @click="selectUser(user)"
        >
          <div class="win11-chip-avatar" :class="user.type">{{ user.username.charAt(0).toUpperCase() }}</div>
          <span class="win11-chip-name">{{ user.username }}</span>
          <span class="win11-chip-type" :class="user.type || 'offline'">{{ getUserTypeLabel(user.type) }}</span>
        </div>
        <div v-if="users.length === 0" class="win11-no-users">{{ t('login.noUsers') }}</div>
      </div>
      <button class="win11-corner-btn" @click="switchToCreateGuest">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        <span>{{ t('login.registerUser') }}</span>
      </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.win11-login {
  width: 100%;
  height: 100%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: transparent;
  position: relative;
  z-index: 2;
}

/* ===== 中央区域 ===== */
.win11-center {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  min-width: 280px;
  max-width: 380px;
}

.login-glass-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  min-width: 280px;
  max-width: 380px;
  padding: 32px 28px;
  border-radius: 16px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border: 1px solid var(--glass-border);
  box-shadow: var(--glass-shadow);
  transition: background 0.3s;
}

/* ===== 头像 ===== */
.win11-avatar {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  background: var(--primary-light);
  color: var(--primary-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 48px;
  font-weight: 300;
  letter-spacing: -1px;
  user-select: none;
  flex-shrink: 0;
}

.win11-avatar.premium {
  background: color-mix(in srgb, #283593 15%, transparent);
  color: #283593;
}

.win11-avatar.guest {
  background: color-mix(in srgb, #E65100 15%, transparent);
  color: #E65100;
}

.win11-avatar.create-mode {
  background: var(--primary-light);
  color: var(--primary-dark);
}

/* ===== 用户名 ===== */
.win11-username {
  font-size: 20px;
  font-weight: 400;
  color: var(--text);
  margin-bottom: 4px;
}

/* ===== 提示文字 ===== */
.win11-hint {
  font-size: 14px;
  color: var(--text-light);
  margin-top: 4px;
}

/* ===== 输入行（带提交按钮） ===== */
.win11-input-row {
  display: flex;
  align-items: center;
  gap: 0;
  width: 240px;
  margin-top: 4px;
}

.win11-input {
  padding: 10px 14px;
  border: 2px solid var(--border);
  border-radius: 4px 0 0 4px;
  font-size: 14px;
  outline: none;
  background: var(--glass-bg-heavy);
  color: var(--text);
  transition: border-color 0.15s;
}

.win11-input:focus { border-color: var(--primary); }
.win11-input::placeholder { color: var(--text-light); }

.win11-input-block {
  width: 100%;
  border-radius: 4px;
  border: 2px solid var(--border);
}

.win11-input-block:focus { border-color: var(--primary); }

.win11-submit-btn {
  height: 40px;
  padding: 0 14px;
  border: 2px solid var(--primary);
  border-left: none;
  border-radius: 0 4px 4px 0;
  background: var(--primary);
  color: white;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: background 0.15s;
  flex-shrink: 0;
}

.win11-submit-btn:hover {
  background: var(--primary-dark);
  border-color: var(--primary-dark);
}

.win11-submit-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ===== 登录按钮 ===== */
.win11-login-btn {
  width: 240px;
  padding: 10px 0;
  border: 2px solid var(--primary);
  border-radius: 4px;
  background: var(--primary);
  color: white;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: background 0.15s;
  margin-top: 4px;
}

.win11-login-btn:hover {
  background: var(--primary-dark);
  border-color: var(--primary-dark);
}

.win11-login-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

/* ===== 类型选择标签 ===== */
.win11-type-tabs {
  display: flex;
  gap: 0;
  border: 2px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
  margin-top: 4px;
}

.win11-type-tab {
  padding: 8px 20px;
  border: none;
  background: var(--glass-bg-heavy);
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  border-right: 1px solid var(--border);
}

.win11-type-tab:last-child { border-right: none; }
.win11-type-tab.active { background: var(--primary); color: white; }
.win11-type-tab:hover:not(.active) { background: var(--glass-bg); }

/* ===== 创建模式表单 ===== */
.win11-form {
  display: flex;
  flex-direction: column;
  gap: 10px;
  width: 240px;
  margin-top: 4px;
  background: var(--glass-bg);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-radius: 12px;
  padding: 16px;
  border: 1px solid var(--glass-border);
}

.win11-form-hint {
  font-size: 12px;
  color: var(--text-light);
  text-align: center;
}

/* ===== 外置登录模板选择 ===== */
.ext-template-row {
  display: flex;
  gap: 6px;
}

.ext-template-btn {
  flex: 1;
  padding: 6px 10px;
  border: 1.5px solid var(--border);
  border-radius: 6px;
  background: var(--glass-bg-heavy);
  color: var(--text-secondary);
  font-size: 12px;
  cursor: pointer;
  transition: all 0.15s;
}

.ext-template-btn.active {
  border-color: var(--primary);
  color: var(--primary);
  background: var(--primary-bg);
}

.ext-template-btn:hover:not(.active) {
  border-color: var(--text-light);
}

.ext-server-name {
  font-size: 12px;
  color: var(--primary);
  text-align: center;
  margin-top: -4px;
}

/* ===== 错误信息 ===== */
.win11-error {
  background: color-mix(in srgb, var(--danger) 12%, transparent);
  color: var(--danger);
  padding: 8px 16px;
  border-radius: 6px;
  font-size: 13px;
  border: 1px solid color-mix(in srgb, var(--danger) 30%, transparent);
  text-align: center;
  width: 100%;
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

/* ===== 正版登录 ===== */
.premium-info {
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  background: var(--glass-bg);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-radius: 12px;
  padding: 20px 16px;
  border: 1px solid var(--glass-border);
}

.premium-desc {
  font-size: 14px;
  color: var(--text);
  font-weight: 500;
}

.premium-hint {
  font-size: 12px;
  color: var(--text-light);
  line-height: 1.5;
  max-width: 260px;
}

.ms-login-box {
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  background: var(--glass-bg);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-radius: 12px;
  padding: 20px 16px;
  border: 1px solid var(--glass-border);
}

.ms-auto-hint {
  display: inline-block;
  background: color-mix(in srgb, var(--success) 15%, transparent);
  color: var(--success);
  padding: 5px 14px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
}

.ms-step-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
}

.ms-step-desc {
  font-size: 13px;
  color: var(--text-secondary);
  text-align: left;
  width: 100%;
}

.ms-url-box {
  background: var(--glass-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 8px 12px;
  font-size: 13px;
  color: var(--primary-dark);
  word-break: break-all;
  font-family: monospace;
  width: 100%;
}

.ms-code-box {
  background: var(--primary-light);
  border: 2px solid var(--primary);
  border-radius: 4px;
  padding: 12px;
  font-size: 24px;
  font-weight: 700;
  color: var(--primary-dark);
  letter-spacing: 4px;
  font-family: monospace;
  width: 100%;
  text-align: center;
}

.ms-progress {
  font-size: 13px;
  color: var(--primary);
  font-weight: 500;
}

.ms-waiting {
  font-size: 12px;
  color: var(--text-light);
}

/* ===== 左下角：用户列表 + 注册按钮 ===== */
.win11-bottom-left {
  position: absolute;
  bottom: 24px;
  left: 24px;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 8px;
}

.bottom-glass-container {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 8px;
  padding: 10px 14px;
  border-radius: 12px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--glass-border);
}

.win11-corner-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  color: var(--text);
  font-size: 13px;
  font-weight: 400;
  cursor: pointer;
  transition: all 0.15s;
}

.win11-corner-btn:hover {
  background: var(--bg-card);
  border-color: var(--text-light);
}

.win11-corner-btn:active {
  background: var(--bg-secondary);
}

/* ===== 右下角用户列表 ===== */
.win11-user-panel {
  display: flex;
  flex-direction: column;
  gap: 4px;
  max-height: 300px;
  overflow-y: auto;
}

.win11-user-chip {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 14px;
  border: 1px solid var(--border);
  border-radius: 4px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}

.win11-user-chip:hover {
  background: var(--glass-bg);
  border-color: var(--text-light);
}

.win11-user-chip.active {
  border-color: var(--primary);
  background: var(--primary-bg);
}

.win11-chip-avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--primary-light);
  color: var(--primary-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 14px;
  font-weight: 400;
  flex-shrink: 0;
}

.win11-chip-avatar.premium {
  background: color-mix(in srgb, #283593 15%, transparent);
  color: #283593;
}

.win11-chip-avatar.guest {
  background: color-mix(in srgb, #E65100 15%, transparent);
  color: #E65100;
}

.win11-chip-avatar.external {
  background: color-mix(in srgb, #2E7D32 15%, transparent);
  color: #2E7D32;
}

.win11-chip-name {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}

.win11-chip-type {
  font-size: 11px;
  padding: 1px 6px;
  border-radius: 3px;
  font-weight: 500;
}

.win11-chip-type.guest {
  background: color-mix(in srgb, #E65100 15%, transparent);
  color: #E65100;
}

.win11-chip-type.offline {
  background: color-mix(in srgb, #2E7D32 15%, transparent);
  color: #2E7D32;
}

.win11-chip-type.premium {
  background: color-mix(in srgb, #283593 15%, transparent);
  color: #283593;
}

.win11-chip-type.external {
  background: color-mix(in srgb, #2E7D32 15%, transparent);
  color: #2E7D32;
}

.win11-no-users {
  font-size: 13px;
  color: var(--text-light);
  padding: 8px 14px;
}

/* ===== 动画 ===== */
@keyframes fadeIn {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}

.fade-in {
  animation: fadeIn 0.25s ease;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.spin {
  animation: spin 1s linear infinite;
}
</style>
