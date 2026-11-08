<script setup>
import { ref, onMounted, onUnmounted, computed, defineAsyncComponent, nextTick, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import LoginPage from './components/LoginPage.vue'
// 主页是首屏，保持同步加载
import MainPage from './components/MainPage.vue'
// 其他页面懒加载，首次访问时才加载组件代码
const DownloadPage = defineAsyncComponent(() => import('./components/DownloadPage.vue'))
const SettingsPage = defineAsyncComponent(() => import('./components/SettingsPage.vue'))
const ModPage = defineAsyncComponent(() => import('./components/ModPage.vue'))
const LicensePage = defineAsyncComponent(() => import('./components/LicensePage.vue'))
const EasyQGLPage = defineAsyncComponent(() => import('./components/EasyQGLPage.vue'))
const QGLPlusPage = defineAsyncComponent(() => import('./components/QGLPlusPage.vue'))
import QGLDialog from './components/QGLDialog.vue'
import {
  CheckFirstRun, GetCurrentUser, IsGuestLocked, UnlockGuest,
  GetDownloadList, GetDownloadListCount, RemoveFromDownloadList, StartDownloadList,
  GetThemeColor, GetBackgroundImageDataURL
} from '../wailsjs/go/main/App.js'
import { EventsOn } from '../wailsjs/runtime/runtime.js'
import { useEasyQGL } from './stores/easyQGL.js'
import { setQGLDialogRef } from './composables/qglDialog.js'
import defaultBg from './assets/images/background.jpg'

const { t } = useI18n()

function cleanError(e) {
  return String(e).replace('Error: ', '')
}

const currentPage = ref('login')
const currentUser = ref(null)
const isFirstRun = ref(false)

const { state: easyQGL } = useEasyQGL()

// 页面过渡动画方向: 'left'(进入) | 'right'(退出)
const transitionName = ref('page-left')

// 主题和背景（backgroundDataURL 存储实际可用的 data URL）
const themeColor = ref('cyan')
const darkMode = ref(false)
const backgroundImageURL = ref('')

// 下载列表相关
const downloadCount = ref(0)
const isDownloading = ref(false)
const showDownloadList = ref(false)
const downloadList = ref([])
const downloadListLoading = ref(false)

// 解锁相关
const unlockPassword = ref('')
const unlockError = ref('')
const unlockLoading = ref(false)
const showUnlockModal = ref(false)

// QGL 弹窗
const qglDialog = ref(null)

// Toast 通知
const toastMessage = ref('')
const toastVisible = ref(false)
let toastTimer = null

// 系统主题监听
let mediaQuery = null
let mediaQueryHandler = null

const isGuestLocked = computed(() => {
  return currentUser.value?.type === 'guest' && currentUser.value?.isLocked
})

const showDownloadBtn = computed(() => {
  return currentPage.value !== 'login'
})

const showUnlockBtn = computed(() => {
  return currentPage.value !== 'login' && isGuestLocked.value
})

// 背景图片样式 - 使用 data URL
const bgStyle = computed(() => {
  const bg = backgroundImageURL.value || defaultBg
  return {
    backgroundImage: `url(${bg})`,
    backgroundSize: 'cover',
    backgroundPosition: 'center',
    backgroundRepeat: 'no-repeat'
  }
})

// 应用深色模式
function applyDarkMode(isDark) {
  darkMode.value = isDark
  const root = document.documentElement
  if (isDark) {
    root.setAttribute('data-mode', 'dark')
  } else {
    root.removeAttribute('data-mode')
  }
}

// 监听深色模式变化
watch(darkMode, (newVal) => {
  localStorage.setItem('qgl-dark-mode', newVal ? 'true' : 'false')
})

function showToast(msg, duration = 3000) {
  toastMessage.value = msg
  toastVisible.value = true
  if (toastTimer) clearTimeout(toastTimer)
  toastTimer = setTimeout(() => {
    toastVisible.value = false
  }, duration)
}

function copyError(msg) {
  navigator.clipboard.writeText(msg).then(() => {
    showToast(t('app.errorCopied'), 2000)
  }).catch(() => {
    const ta = document.createElement('textarea')
    ta.value = msg
    ta.style.position = 'fixed'
    ta.style.left = '-9999px'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
    showToast(t('app.errorCopied'), 2000)
  })
}

async function loadThemeAndBg() {
  const [themeResult, bgResult] = await Promise.allSettled([
    GetThemeColor(),
    GetBackgroundImageDataURL()
  ])
  if (themeResult.status === 'fulfilled' && themeResult.value) {
    themeColor.value = themeResult.value
    document.documentElement.setAttribute('data-theme', themeColor.value)
  }
  if (bgResult.status === 'fulfilled' && bgResult.value) {
    backgroundImageURL.value = bgResult.value
  }
}

// 初始化深色模式
function initDarkMode() {
  const saved = localStorage.getItem('qgl-dark-mode')
  if (saved !== null) {
    applyDarkMode(saved === 'true')
    return
  }

  mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  applyDarkMode(mediaQuery.matches)

  mediaQueryHandler = (e) => {
    if (localStorage.getItem('qgl-dark-mode') === null) {
      applyDarkMode(e.matches)
    }
  }
  mediaQuery.addEventListener('change', mediaQueryHandler)
}

onMounted(async () => {
  nextTick(() => {
    if (qglDialog.value) {
      setQGLDialogRef(qglDialog.value)
    }
  })

  initDarkMode()

  EventsOn('launchStatus', (status) => {
    if (status === 'fixing') showToast(t('app.fixing'), 5000)
    else if (status === 'launching') showToast(t('app.launching'), 5000)
    else if (status === 'success') showToast(t('app.launchSuccess'))
    else if (status === 'timeout') showToast(t('app.launchTimeout'), 5000)
    else if (status === 'crashed') showToast(t('app.crashed'), 5000)
  })

  EventsOn('crashInfo', (info) => {
    if (info) showToast(t('app.crashReason') + info, 8000)
  })

  EventsOn('downloadListUpdated', (items) => {
    downloadList.value = items || []
    downloadCount.value = items ? items.length : 0
  })

  EventsOn('downloadProgress', () => {
    refreshDownloadCount()
    refreshDownloadList()
  })

  EventsOn('themeChanged', (color) => {
    themeColor.value = color || 'cyan'
    document.documentElement.setAttribute('data-theme', themeColor.value)
  })

  EventsOn('backgroundChanged', async () => {
    try {
      const url = await GetBackgroundImageDataURL()
      backgroundImageURL.value = url || ''
    } catch (e) {
      console.error('加载背景图片失败:', e)
    }
  })

  EventsOn('downloadListCompleted', () => {
    isDownloading.value = false
  })

  const [, userCheckResult] = await Promise.allSettled([
    loadThemeAndBg(),
    (async () => {
      const firstRun = await CheckFirstRun()
      isFirstRun.value = firstRun
      if (firstRun) {
        currentPage.value = 'login'
        return
      }
      const user = await GetCurrentUser()
      if (user && user.username) {
        if (user.type === 'guest') {
          try { user.isLocked = await IsGuestLocked() } catch { user.isLocked = false }
          currentUser.value = user
          currentPage.value = 'main'
        } else {
          user.isLocked = false
          if (user.hasPassword) {
            currentPage.value = 'login'
          } else {
            currentUser.value = user
            currentPage.value = 'main'
          }
        }
      } else {
        currentPage.value = 'login'
      }
    })()
  ])

  refreshDownloadCount()
})

onUnmounted(() => {
  if (toastTimer) clearTimeout(toastTimer)
  if (mediaQuery && mediaQueryHandler) {
    mediaQuery.removeEventListener('change', mediaQueryHandler)
  }
})

async function refreshDownloadCount() {
  try { downloadCount.value = await GetDownloadListCount() } catch (e) {
    console.error('获取下载计数失败:', e)
    downloadCount.value = 0
  }
}

async function refreshDownloadList() {
  if (!showDownloadList.value) return
  try { downloadList.value = await GetDownloadList() || [] } catch (e) {
    console.error('获取下载列表失败:', e)
  }
}

function onLoginSuccess(user) {
  currentUser.value = user
  transitionName.value = 'page-fade'
  currentPage.value = 'main'
  refreshDownloadCount()
  loadThemeAndBg()
}

function navigateTo(page) {
  if (page === 'main' || page === 'login') {
    transitionName.value = 'page-right'
  } else {
    transitionName.value = 'page-left'
  }
  currentPage.value = page
}

function onLogout() {
  transitionName.value = 'page-right'
  currentUser.value = null
  currentPage.value = 'login'
}

function goToAddUser() {
  transitionName.value = 'page-right'
  currentUser.value = null
  currentPage.value = 'login'
}

function showLicensePage() {
  transitionName.value = 'page-left'
  currentPage.value = 'license'
}

function closeLicensePage() {
  transitionName.value = 'page-right'
  currentPage.value = 'settings'
}

async function openDownloadList() {
  if (isGuestLocked.value) return
  showDownloadList.value = true
  downloadListLoading.value = true
  try { downloadList.value = await GetDownloadList() || [] } catch (e) {
    console.error('获取下载列表失败:', e)
    downloadList.value = []
  } finally { downloadListLoading.value = false }
}

async function removeDownloadItem(item) {
  try {
    await RemoveFromDownloadList(item.customName)
    downloadList.value = await GetDownloadList() || []
    downloadCount.value = await GetDownloadListCount()
  } catch (e) {
    console.error('移除下载项失败:', e)
  }
}

async function startDownload() {
  try {
    await StartDownloadList()
    isDownloading.value = true
    showToast(t('app.downloadStarted'))
  } catch (e) {
    showToast(t('app.downloadFailed') + cleanError(e))
  }
}

function openUnlockModal() {
  unlockPassword.value = ''
  unlockError.value = ''
  showUnlockModal.value = true
}

async function handleUnlock() {
  if (!unlockPassword.value.trim()) { unlockError.value = t('app.enterSecurityPasswordError'); return }
  unlockLoading.value = true
  unlockError.value = ''
  try {
    await UnlockGuest(unlockPassword.value.trim())
    currentUser.value.isLocked = false
    showUnlockModal.value = false
    showToast(t('app.unlocked'))
  } catch (e) {
    unlockError.value = cleanError(e)
  } finally { unlockLoading.value = false }
}

defineExpose({
  toggleDarkMode: () => applyDarkMode(!darkMode.value),
  darkMode
})
</script>

<template>
  <div class="app-container" :data-theme="themeColor">
    <!-- 背景图片层 -->
    <div class="bg-layer" :style="bgStyle"></div>
    <!-- 半透明遮罩层 -->
    <div class="bg-overlay" :class="{ 'dark': darkMode }"></div>

    <!-- 页面内容 + 过渡动画 -->
    <Transition :name="transitionName" mode="out-in">
      <LoginPage
        v-if="currentPage === 'login'"
        key="login"
        :isFirstRun="isFirstRun"
        @login-success="onLoginSuccess"
      />
      <MainPage
        v-else-if="currentPage === 'main'"
        key="main"
        :currentUser="currentUser"
        @navigate="navigateTo"
        @logout="onLogout"
        @add-user="goToAddUser"
      />
      <DownloadPage
        v-else-if="currentPage === 'download'"
        key="download"
        :currentUser="currentUser"
        @navigate="navigateTo"
      />
      <SettingsPage
        v-else-if="currentPage === 'settings'"
        key="settings"
        :currentUser="currentUser"
        @navigate="navigateTo"
        @logout="onLogout"
        @show-license="showLicensePage"
      />
      <ModPage
        v-else-if="currentPage === 'mod'"
        key="mod"
        :currentUser="currentUser"
        @navigate="navigateTo"
      />
      <LicensePage
        v-else-if="currentPage === 'license'"
        key="license"
        :currentUser="currentUser"
        @back="closeLicensePage"
      />
      <EasyQGLPage
        v-else-if="currentPage === 'easyqgl'"
        key="easyqgl"
        :currentUser="currentUser"
        @navigate="navigateTo"
      />
      <QGLPlusPage
        v-else-if="currentPage === 'qglplus'"
        key="qglplus"
        :currentUser="currentUser"
        @navigate="navigateTo"
      />
    </Transition>

    <!-- 全局下载列表按钮 -->
    <button v-if="showDownloadBtn" class="global-download-btn" :class="{ 'easy-orange-btn': easyQGL.active }" :disabled="isGuestLocked" :title="isGuestLocked ? t('app.guestLockedDownload') : t('app.downloadListTitle')" @click="openDownloadList">
      <span class="download-icon">&#x2B07;</span>
      <span v-if="downloadCount > 0" class="download-badge">{{ downloadCount }}</span>
    </button>

    <!-- 全局解锁按钮 -->
    <button v-if="showUnlockBtn" class="global-unlock-btn" :title="t('app.unlockGuest')" @click="openUnlockModal">&#x1F512;</button>

    <!-- Toast 通知 -->
    <Transition name="toast">
      <div v-if="toastVisible" class="toast-notification">{{ toastMessage }}</div>
    </Transition>

    <!-- 下载列表弹窗 -->
    <div v-if="showDownloadList" class="modal-overlay" @click.self="showDownloadList = false">
      <div class="modal-content fade-in" :class="{ 'easy-orange': easyQGL.active }" style="min-width: 420px;">
        <div class="modal-title">
          {{ t('app.downloadList') }}
          <span v-if="easyQGL.active" class="easy-badge">Easy QGL</span>
        </div>
        <div v-if="downloadListLoading" class="loading-hint">{{ t('app.loading') }}</div>
        <div v-else-if="downloadList.length === 0" class="empty-hint">{{ t('app.downloadListEmpty') }}</div>
        <div v-else class="dl-list">
          <div v-for="(item, index) in downloadList" :key="index" class="dl-item">
            <div class="dl-item-info">
              <div class="dl-item-name">{{ item.customName || item.id }}</div>
              <div class="dl-item-status">
                <span v-if="item.status === 'pending'" class="status-pending">{{ t('app.statusPending') }}</span>
                <span v-else-if="item.status === 'downloading'" class="status-downloading">{{ t('app.statusDownloading') }}</span>
                <span v-else-if="item.status === 'completed'" class="status-completed">{{ t('app.statusCompleted') }}</span>
                <span v-else-if="item.status === 'failed'" class="status-failed">{{ t('app.statusFailed') }}</span>
              </div>
              <div v-if="item.status === 'failed' && item.errorMsg" class="dl-error" :title="t('app.clickToCopyError')" @click="copyError(item.errorMsg)">{{ item.errorMsg }}</div>
              <div v-if="item.status === 'downloading'" class="dl-progress">
                <div class="progress-bar"><div class="progress-bar-fill" :style="{ width: (item.progress || 0) + '%' }"></div></div>
                <span class="dl-progress-text">{{ (item.progress || 0).toFixed(1) }}%</span>
              </div>
            </div>
            <div class="dl-item-actions">
              <button v-if="item.status !== 'downloading'" class="btn-icon-sm" :title="t('app.remove')" @click="removeDownloadItem(item)">&#x2716;</button>
            </div>
          </div>
        </div>
        <div class="dl-footer">
          <button
            class="btn"
            :class="easyQGL.active ? 'btn-easy-orange' : 'btn-primary'"
            :disabled="downloadList.length === 0 || isDownloading"
            @click="startDownload"
          >{{ isDownloading ? t('app.downloading') : t('app.startDownload') }}</button>
          <button class="btn btn-outline" @click="showDownloadList = false">{{ t('app.close') }}</button>
        </div>
      </div>
    </div>

    <!-- 解锁弹窗 -->
    <div v-if="showUnlockModal" class="modal-overlay" @click.self="showUnlockModal = false">
      <div class="modal-content fade-in" style="min-width: 360px;">
        <div class="modal-title">{{ t('app.unlockGuest') }}</div>
        <div v-if="unlockError" class="error-msg">{{ unlockError }}</div>
        <div class="form-group">
          <label>{{ t('app.securityPassword') }}</label>
          <input v-model="unlockPassword" type="password" class="input" :placeholder="t('app.enterSecurityPassword')" @keyup.enter="handleUnlock"/>
        </div>
        <div class="dl-footer">
          <button class="btn btn-primary" :disabled="unlockLoading" @click="handleUnlock">{{ unlockLoading ? t('app.unlocking') : t('app.unlock') }}</button>
          <button class="btn btn-outline" @click="showUnlockModal = false">{{ t('app.cancel') }}</button>
        </div>
      </div>
    </div>

    <!-- QGL 自定义弹窗 -->
    <QGLDialog ref="qglDialog" />
  </div>
</template>

<style scoped>
.app-container {
  width: 100vw;
  height: 100vh;
  overflow: hidden;
  position: relative;
}

/* ====== 页面过渡动画 ====== */
.page-left-enter-active,
.page-right-enter-active,
.page-fade-enter-active {
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
.page-left-leave-active,
.page-right-leave-active,
.page-fade-leave-active {
  transition: all 0.25s cubic-bezier(0.4, 0, 1, 1);
}

/* 从右侧滑入（前进：主页→设置/下载/MOD） */
.page-left-enter-from {
  opacity: 0;
  transform: translateX(40px);
}
.page-left-leave-to {
  opacity: 0;
  transform: translateX(-20px);
}

/* 向右滑出（后退：设置/下载→主页） */
.page-right-enter-from {
  opacity: 0;
  transform: translateX(-40px);
}
.page-right-leave-to {
  opacity: 0;
  transform: translateX(20px);
}

/* 淡入淡出（登录↔主页） */
.page-fade-enter-from,
.page-fade-leave-to {
  opacity: 0;
  transform: scale(0.97);
}

/* ====== 背景层 ====== */
.bg-layer {
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  z-index: 0;
  transition: background-image 0.5s ease;
}

.bg-overlay {
  position: fixed;
  top: 0; left: 0;
  width: 100%; height: 100%;
  z-index: 1;
  background: rgba(255, 255, 255, 0.15);
  pointer-events: none;
  transition: background 0.3s ease;
}

.bg-overlay.dark {
  background: rgba(0, 0, 0, 0.4);
}

/* ====== 全局按钮 ====== */
.global-download-btn {
  position: fixed;
  bottom: 24px; right: 24px;
  width: 48px; height: 48px;
  background: var(--glass-bg-heavy);
  color: var(--primary);
  border: 1px solid var(--glass-border);
  border-radius: 50%;
  font-size: 20px;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  box-shadow: var(--glass-shadow);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  transition: all 0.2s;
  z-index: 100;
}
.global-download-btn:hover:not(:disabled) { background: var(--primary); color: white; transform: scale(1.05); }
.global-download-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.download-icon { font-size: 20px; line-height: 1; }
.download-badge {
  position: absolute; top: -4px; right: -4px;
  min-width: 18px; height: 18px;
  background: var(--danger); color: white;
  border-radius: 9px;
  font-size: 11px; font-weight: 600;
  display: flex; align-items: center; justify-content: center;
  padding: 0 4px;
}

.global-unlock-btn {
  position: fixed;
  bottom: 24px; right: 82px;
  width: 48px; height: 48px;
  background: var(--glass-bg-heavy);
  color: var(--warning);
  border: 1px solid var(--glass-border);
  border-radius: 50%;
  font-size: 20px;
  cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  box-shadow: var(--glass-shadow);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  transition: all 0.2s;
  z-index: 100;
}
.global-unlock-btn:hover { background: var(--warning); color: white; transform: scale(1.05); }

/* Toast */
.toast-notification {
  position: fixed;
  top: 24px; left: 50%; transform: translateX(-50%);
  background: var(--glass-bg-heavy);
  color: var(--text);
  padding: 10px 24px; border-radius: 8px;
  font-size: 14px; font-weight: 500;
  z-index: 2000;
  box-shadow: var(--glass-shadow);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--glass-border);
  pointer-events: none;
}
.toast-enter-active { transition: all 0.3s ease; }
.toast-leave-active { transition: all 0.3s ease; }
.toast-enter-from { opacity: 0; transform: translateX(-50%) translateY(-20px); }
.toast-leave-to { opacity: 0; transform: translateX(-50%) translateY(-20px); }

/* 下载列表 */
.dl-list { max-height: 300px; overflow-y: auto; }
.dl-item {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 12px; border-radius: 8px; transition: background 0.15s;
}
.dl-item:hover { background: var(--primary-bg); }
.dl-item-info { flex: 1; min-width: 0; }
.dl-item-name { font-size: 14px; font-weight: 500; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dl-item-status { font-size: 12px; color: var(--text-light); margin-top: 2px; }
.status-pending { color: var(--text-light); }
.status-downloading { color: var(--primary); font-weight: 500; }
.status-completed { color: var(--success); font-weight: 500; }
.status-failed { color: var(--danger); font-weight: 500; }
.dl-progress { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.dl-progress .progress-bar { flex: 1; height: 4px; background: var(--bg-card); border-radius: 2px; overflow: hidden; }
.dl-progress .progress-bar-fill { height: 100%; background: var(--primary); border-radius: 2px; transition: width 0.3s; }
.dl-progress-text { font-size: 11px; color: var(--primary-dark); font-weight: 600; min-width: 40px; text-align: right; }
.dl-item-actions { display: flex; gap: 4px; margin-left: 12px; flex-shrink: 0; }
.btn-icon-sm {
  width: 28px; height: 28px; border: none; background: transparent;
  color: var(--text-light); border-radius: 50%; cursor: pointer;
  display: flex; align-items: center; justify-content: center;
  font-size: 14px; transition: all 0.15s;
}
.btn-icon-sm:hover { background: color-mix(in srgb, var(--danger) 15%, transparent); color: var(--danger); }
.dl-footer { display: flex; gap: 10px; margin-top: 16px; justify-content: flex-end; }
.loading-hint { text-align: center; color: var(--text-light); padding: 20px; font-size: 14px; }
.empty-hint { text-align: center; color: var(--text-light); padding: 20px; font-size: 14px; }
.error-msg {
  background: color-mix(in srgb, var(--danger) 12%, transparent);
  color: var(--danger);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  margin-bottom: 16px;
  border: 1px solid color-mix(in srgb, var(--danger) 30%, transparent);
}
.dl-error {
  color: var(--danger);
  font-size: 12px;
  margin-top: 4px;
  padding: 6px 8px;
  background: color-mix(in srgb, var(--danger) 10%, transparent);
  border-radius: 4px;
  border: 1px solid color-mix(in srgb, var(--danger) 20%, transparent);
  word-break: break-all;
  line-height: 1.5;
  cursor: pointer;
  user-select: text;
  transition: background 0.15s;
}
.dl-error:hover { background: color-mix(in srgb, var(--danger) 20%, transparent); }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 13px; font-weight: 500; color: var(--text-secondary); margin-bottom: 6px; }

/* Easy QGL 橙色主题 */
.easy-orange {
  border-color: color-mix(in srgb, var(--easy-orange, #FF9800) 30%, transparent) !important;
}

.easy-badge {
  display: inline-block;
  margin-left: 8px;
  padding: 2px 8px;
  background: var(--easy-orange, #FF9800);
  color: white;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  vertical-align: middle;
}

.btn-easy-orange {
  background: var(--easy-orange, #FF9800);
  border-color: var(--easy-orange, #FF9800);
  color: white;
  padding: 8px 20px;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
}

.btn-easy-orange:hover:not(:disabled) {
  background: var(--easy-orange-dark, #F57C00);
}

.btn-easy-orange:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.easy-orange-btn {
  color: var(--easy-orange, #FF9800) !important;
  border-color: color-mix(in srgb, var(--easy-orange, #FF9800) 40%, transparent) !important;
}

.easy-orange-btn:hover:not(:disabled) {
  background: var(--easy-orange, #FF9800) !important;
  color: white !important;
}

.easy-orange .dl-progress .progress-bar-fill {
  background: var(--easy-orange, #FF9800);
}

.easy-orange .dl-progress-text {
  color: var(--easy-orange-dark, #E65100);
}
</style>
