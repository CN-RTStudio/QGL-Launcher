<script setup>
import { ref, onMounted, computed, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  GetCurrentUser, SetCurrentUser, GetInstalledVersions, ScanVersions,
  GetSelectedVersion, SetSelectedVersion, LaunchGame, IsVersionIsolation,
  SetVersionIsolation, GetRecommendedJavaForVersion, AddJavaToDownloadList,
  StartDownloadList, GetLaunchCommand, GetShowExportLaunchCommand
} from '../../wailsjs/go/main/App.js'
import { EventsOn } from '../../wailsjs/runtime/runtime.js'
import { useEasyQGL } from '../stores/easyQGL.js'
import { showQGLDialog } from '../composables/qglDialog.js'

const props = defineProps({
  currentUser: Object
})

const emit = defineEmits(['navigate', 'logout', 'add-user'])

const { t } = useI18n()

function cleanError(e) {
  return String(e).replace('Error: ', '')
}

const currentUser = ref(props.currentUser || { username: 'Player', hasPassword: false, type: 'offline', isLocked: false })

// 同步父组件的 currentUser 变化（如解锁后 isLocked 更新）
watch(() => props.currentUser, (newVal) => {
  if (newVal) currentUser.value = { ...newVal }
}, { deep: true })

const installedVersions = ref([])
const selectedVersion = ref('')
const showUserList = ref(false)
const showVersionList = ref(false)
const users = ref([])
const versionIsolation = ref(false)
const launching = ref(false)
const launchMsg = ref('')
const launchMsgType = ref('') // '' | 'success' | 'error' | 'info'
const showExportLaunchBtn = ref(false)

const tips = [
  '你知道吗？你不知道:D',
  '注册个热土用户 id.rtstu.com 球球你了 :(',
  '你知道吗？其实我的世界最开始叫Cave Game',
  'QGL全称其实是QingLong Luncher 是哒~ 我们拼写错误了 变成"午餐器"啦 qwq',
  '为什么QingLong Luncher不叫QLL？因为不好听 :)',
  'RTSDNYYDS',
  'Hello RT',
  '要致富，先撸树',
  '大手牵小手，一起骗新手 awa'
]
const randomTip = ref('')
const showTip = ref(false)

const { state: easyQGL, enterModFirstMode, exitMode } = useEasyQGL()

const isGuestLocked = computed(() => currentUser.value.type === 'guest' && currentUser.value.isLocked)

function clearLaunchMsg() {
  launchMsg.value = ''
  launchMsgType.value = ''
  showTip.value = false
}

onMounted(async () => {
  await refreshData()
  EventsOn('launchStatus', (status) => {
    if (status === 'fixing') {
      launchMsg.value = t('main.fixingFiles')
      launchMsgType.value = 'info'
    } else if (status === 'launching') {
      launchMsg.value = t('main.waitingForWindow')
      launchMsgType.value = 'info'
    } else if (status === 'success') {
      launchMsg.value = t('main.launchSuccess')
      launchMsgType.value = 'success'
      launching.value = false
      setTimeout(clearLaunchMsg, 3000)
    } else if (status === 'timeout') {
      launchMsg.value = t('main.launchTimeout')
      launchMsgType.value = 'error'
      launching.value = false
    } else if (status === 'crashed') {
      launchMsg.value = t('main.gameCrashed')
      launchMsgType.value = 'error'
      launching.value = false
    }
  })

  EventsOn('crashInfo', (info) => {
    if (info) {
      launchMsg.value = t('main.gameCrashInfo') + info
      launchMsgType.value = 'error'
    }
  })

  try { showExportLaunchBtn.value = await GetShowExportLaunchCommand() } catch (e) { console.error('获取导出启动命令设置失败:', e) }
})

async function refreshData() {
  const [userResult, versionsResult, selectedResult, isolationResult] = await Promise.allSettled([
    GetCurrentUser(),
    GetInstalledVersions(),
    GetSelectedVersion(),
    IsVersionIsolation()
  ])

  if (userResult.status === 'fulfilled' && userResult.value?.username) {
    currentUser.value = userResult.value
  }

  if (versionsResult.status === 'fulfilled' && versionsResult.value) {
    installedVersions.value = versionsResult.value
  } else {
    installedVersions.value = []
  }

  if (selectedResult.status === 'fulfilled' && selectedResult.value) {
    selectedVersion.value = selectedResult.value
  }

  if (!selectedVersion.value && installedVersions.value.length > 0) {
    selectedVersion.value = installedVersions.value[0].folderName
    try { await SetSelectedVersion(selectedVersion.value) } catch (e) { console.error('设置默认版本失败:', e) }
  }

  if (isolationResult.status === 'fulfilled') {
    versionIsolation.value = isolationResult.value
  }
}

async function showSwitchUser() {
  if (isGuestLocked.value) return
  emit('logout')
}

async function selectUser(user) {
  showUserList.value = false
  if (user.hasPassword) {
    emit('logout')
  } else {
    try {
      await SetCurrentUser(user.username)
      currentUser.value = user
    } catch (e) {
      console.error('切换用户失败:', e)
    }
  }
}

const versionListLoading = ref(false)

async function showVersionSelect() {
  showVersionList.value = true
  versionListLoading.value = true
  try {
    const versions = await ScanVersions()
    installedVersions.value = versions || []
    if (installedVersions.value.length > 0 && !installedVersions.value.find(v => v.folderName === selectedVersion.value)) {
      selectedVersion.value = installedVersions.value[0].folderName
      try { await SetSelectedVersion(selectedVersion.value) } catch (e) { console.error('设置选中版本失败:', e) }
    }
  } catch (e) {
    console.error('扫描游戏版本失败:', e)
  } finally {
    versionListLoading.value = false
  }
}

async function selectVersion(ver) {
  selectedVersion.value = ver.folderName
  showVersionList.value = false
  try { await SetSelectedVersion(ver.folderName) } catch (e) { console.error('设置选中版本失败:', e) }
}

async function handleLaunch() {
  if (!selectedVersion.value) {
    launchMsg.value = t('main.selectVersionFirst')
    launchMsgType.value = 'error'
    return
  }
  launching.value = true
  launchMsg.value = t('main.launchingGame')
  launchMsgType.value = 'info'
  randomTip.value = tips[Math.floor(Math.random() * tips.length)]
  showTip.value = true
  try {
    await LaunchGame(selectedVersion.value)
  } catch (e) {
    const errMsg = cleanError(e)
    launching.value = false

    if (errMsg.includes('Java 选择失败') || (errMsg.includes('未找到') && errMsg.includes('Java'))) {
      try {
        const recJava = await GetRecommendedJavaForVersion(selectedVersion.value)
        if (recJava > 0) {
          await AddJavaToDownloadList(recJava)
          try { await StartDownloadList() } catch (err) { console.error('开始下载列表失败:', err) }
          launchMsg.value = t('main.javaAutoDownloaded', { version: recJava })
          launchMsgType.value = 'info'
          return
        }
      } catch (err) {
        console.error('获取推荐Java版本失败:', err)
      }
    }

    launchMsg.value = t('main.launchFailed') + errMsg
    launchMsgType.value = 'error'
  }
}

async function toggleVersionIsolation() {
  try {
    await SetVersionIsolation(!versionIsolation.value)
    versionIsolation.value = !versionIsolation.value
  } catch (e) {
    console.error('切换版本隔离失败:', e)
  }
}

async function handleExportLaunchCommand() {
  if (!selectedVersion.value) {
    launchMsg.value = t('main.selectVersionFirst')
    launchMsgType.value = 'error'
    return
  }
  try {
    const cmd = await GetLaunchCommand(selectedVersion.value)
    const btnIndex = await showQGLDialog({
      theme: 'normal',
      title: t('main.exportLaunchCommandTitle'),
      content: cmd,
      btn1Label: t('main.exportLaunchCommandBtn1'),
      btn2Label: t('main.exportLaunchCommandBtn2'),
    })
    if (btnIndex === 1) {
      try {
        await navigator.clipboard.writeText(cmd)
      } catch {
        const ta = document.createElement('textarea')
        ta.value = cmd
        ta.style.position = 'fixed'
        ta.style.left = '-9999px'
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
      }
    }
  } catch (e) {
    const errMsg = cleanError(e)
    await showQGLDialog({
      theme: 'error',
      title: t('main.exportLaunchCommandTitle'),
      content: t('main.exportLaunchCommandFailed') + errMsg,
      btn1Label: t('main.exportLaunchCommandBtn2'),
    })
  }
}

const displayVersion = computed(() => {
  if (!selectedVersion.value) return t('main.noVersionSelected')
  const ver = installedVersions.value.find(v => v.folderName === selectedVersion.value)
  if (!ver) return selectedVersion.value
  let display = ''
  if (ver.name) display += ver.name + ' - '
  display += ver.version
  if (ver.loader) display += ' (' + ver.loader + ')'
  return display
})

const userTypeLabel = computed(() => {
  if (currentUser.value.type === 'guest') return t('main.guestMode')
  if (currentUser.value.type === 'premium') return t('main.premiumMode')
  if (currentUser.value.type === 'external') return t('main.externalMode')
  return t('main.offlineMode')
})
</script>

<template>
  <div class="main-page">
    <!-- 左侧主面板 -->
    <div class="left-panel">
      <!-- 用户信息区域 -->
      <div class="user-section">
        <div class="user-card">
          <div class="user-avatar-large">{{ currentUser.username?.charAt(0).toUpperCase() || 'P' }}</div>
          <div class="user-detail">
            <div class="user-name-large">
              {{ currentUser.username || 'Player' }}
              <span v-if="isGuestLocked" class="lock-badge" :title="t('main.guestLockedTooltip')">&#x1F512;</span>
            </div>
            <div class="user-status">
              {{ userTypeLabel }}
              <span v-if="isGuestLocked" class="lock-hint">（{{ t('main.locked') }}）</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 功能按钮区域 -->
      <div class="action-section">
        <button class="action-btn" :disabled="isGuestLocked" @click="showSwitchUser">
          <span class="action-icon">&#x1F464;</span>
          <span class="action-text">{{ t('main.switchUser') }}</span>
        </button>

        <button class="action-btn" @click="showVersionSelect">
          <span class="action-icon">&#x1F4E6;</span>
          <span class="action-text">{{ t('main.switchVersion') }}</span>
          <span class="action-hint">{{ displayVersion }}</span>
        </button>

        <button
          class="launch-btn"
          :disabled="launching || !selectedVersion"
          @click="handleLaunch"
        >
          <span v-if="launching" class="spin" style="display:inline-block;">&#x2699;</span>
          <span v-else>&#x25B6;</span>
          <span>{{ launching ? t('main.launching') : t('main.launchGame') }}</span>
          <span class="launch-version">{{ displayVersion }}</span>
        </button>

        <button
          v-if="showExportLaunchBtn && selectedVersion"
          class="export-cmd-btn"
          @click="handleExportLaunchCommand"
        >
          &#x1F4CB; {{ t('main.exportLaunchCommand') }}
        </button>

        <div v-if="showTip" class="tip-box">
          <span class="tip-label">{{ t('main.tip') }}</span>
          <span class="tip-content">{{ randomTip }}</span>
        </div>

        <div v-if="launchMsg" class="launch-msg-glass">
          <div class="launch-msg" :class="launchMsgType">{{ launchMsg }}</div>
        </div>

        <!-- 版本隔离开关 -->
        <div class="isolation-row">
          <div class="tooltip-wrapper">
            <label class="toggle">
              <input type="checkbox" v-model="versionIsolation" @change="toggleVersionIsolation" />
              <span class="toggle-slider"></span>
            </label>
            <span class="tooltip-text">{{ t('main.suggestEnableInSettings') }}</span>
          </div>
          <span class="isolation-label">{{ t('main.versionIsolation') }}</span>
        </div>
      </div>
    </div>

    <!-- 右侧功能区域 -->
    <div class="right-panel">
      <div class="right-glass-container">
      <div class="right-content">
        <h2 class="welcome-title">{{ t('main.welcomeBack') }}{{ currentUser.username || t('main.player') }}</h2>
        <p class="welcome-desc">{{ t('main.selectFeature') }}</p>

        <div class="feature-cards">
          <div
            v-if="!isGuestLocked"
            class="feature-card"
            @click="emit('navigate', 'download')"
          >
            <div class="feature-icon">&#x2B07;</div>
            <div class="feature-name">{{ t('main.downloadGame') }}</div>
            <div class="feature-desc">{{ t('main.downloadGameDesc') }}</div>
          </div>

          <div
            class="feature-card"
            @click="emit('navigate', 'mod')"
          >
            <div class="feature-icon">&#x1F4E6;</div>
            <div class="feature-name">{{ t('main.modManage') }}</div>
            <div class="feature-desc">{{ t('main.modManageDesc') }}</div>
          </div>

          <div
            v-if="!isGuestLocked"
            class="feature-card"
            @click="emit('navigate', 'settings')"
          >
            <div class="feature-icon">&#x2699;</div>
            <div class="feature-name">{{ t('main.settings') }}</div>
            <div class="feature-desc">{{ t('main.settingsDesc') }}</div>
          </div>

          <div
            v-if="!isGuestLocked"
            class="feature-card easy-qgl-card"
            @click="emit('navigate', 'easyqgl')"
          >
            <div class="feature-icon">&#x2728;</div>
            <div class="feature-name">{{ t('main.easyQGL') }}</div>
            <div class="feature-desc">{{ t('main.easyQGLDesc') }}</div>
          </div>

          <div
            v-if="!isGuestLocked"
            class="feature-card qglplus-card"
            @click="emit('navigate', 'qglplus')"
          >
            <div class="feature-icon">&#x1F3AE;</div>
            <div class="feature-name">QGLPlus</div>
            <div class="feature-desc">{{ t('main.qglplusDesc') }}</div>
          </div>

          <div v-if="isGuestLocked" class="locked-notice">
            <div class="locked-icon">&#x1F512;</div>
            <div class="locked-text">{{ t('main.guestLocked') }}</div>
            <div class="locked-sub">{{ t('main.guestLockedSub') }}</div>
          </div>
        </div>
      </div>
      </div>

      <!-- 版权信息 -->
      <div class="copyright">
        &copy; 2026 {{ t('main.copyright').replace('© 2026 ', '') }}
      </div>
    </div>

    <!-- 用户列表弹窗 -->
    <div v-if="showUserList" class="modal-overlay" @click.self="showUserList = false">
      <div class="modal-content fade-in">
        <div class="modal-title">{{ t('main.switchUserTitle') }}</div>
        <div class="user-list">
          <div
            v-for="user in users"
            :key="user.username"
            class="user-item"
            :class="{ active: user.username === currentUser.username }"
            @click="selectUser(user)"
          >
            <div class="user-avatar">{{ user.username.charAt(0).toUpperCase() }}</div>
            <div class="user-info">
              <div class="user-name">{{ user.username }}</div>
              <div class="user-pwd-hint">{{ user.hasPassword ? t('main.hasPassword') : t('main.noPassword') }}</div>
            </div>
            <span v-if="user.username === currentUser.username" class="current-badge">{{ t('main.current') }}</span>
          </div>
        </div>
        <div class="add-user-option" @click="showUserList = false; emit('add-user')">
          <span class="add-user-icon">+</span>
          <span>{{ t('main.addNewUser') }}</span>
        </div>
        <button class="btn btn-outline btn-block" @click="showUserList = false" style="margin-top: 12px;">{{ t('app.cancel') }}</button>
      </div>
    </div>

    <!-- 版本选择弹窗 -->
    <div v-if="showVersionList" class="modal-overlay" @click.self="showVersionList = false">
      <div class="modal-content fade-in" style="min-width: 400px;">
        <div class="modal-title">{{ t('main.selectGameVersion') }}</div>
        <div v-if="versionListLoading" class="empty-hint">{{ t('main.scanningVersions') }}</div>
        <div v-else-if="installedVersions.length === 0" class="empty-hint">
          {{ t('main.noInstalledVersion') }}
        </div>
        <div v-else class="version-list">
          <div
            v-for="ver in installedVersions"
            :key="ver.folderName"
            class="version-item"
            :class="{ active: ver.folderName === selectedVersion }"
            @click="selectVersion(ver)"
          >
            <span class="version-name">
              <span v-if="ver.name">{{ ver.name }} - </span>{{ ver.version }}
              <span v-if="ver.loader" class="version-loader-tag">{{ ver.loader }}</span>
            </span>
            <span v-if="ver.folderName === selectedVersion" class="current-badge">{{ t('main.selected') }}</span>
          </div>
        </div>
        <button class="btn btn-outline btn-block" @click="showVersionList = false" style="margin-top: 12px;">{{ t('app.cancel') }}</button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.main-page {
  display: flex;
  width: 100%;
  height: 100%;
  background: transparent;
  position: relative;
  z-index: 2;
}

.left-panel {
  width: 320px;
  min-width: 280px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border-right: 1px solid var(--glass-border);
  display: flex;
  flex-direction: column;
  padding: 24px 20px;
  transition: background 0.3s;
}

.user-section {
  margin-bottom: 24px;
}

.user-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--glass-border);
  border-radius: 12px;
}

.user-avatar-large {
  width: 52px;
  height: 52px;
  background: var(--primary);
  color: white;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 22px;
  font-weight: 700;
  flex-shrink: 0;
}

.user-name-large {
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
  display: flex;
  align-items: center;
  gap: 6px;
}

.lock-badge {
  font-size: 14px;
  cursor: help;
}

.user-status {
  font-size: 12px;
  color: var(--text-light);
  margin-top: 2px;
}

.lock-hint {
  color: var(--danger);
  font-weight: 500;
}

.action-section {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.15s;
  font-size: 14px;
  color: var(--text);
}

.action-btn:hover:not(:disabled) {
  border-color: var(--primary);
  background: var(--primary-bg);
}

.action-btn:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.action-icon {
  font-size: 18px;
}

.action-text {
  font-weight: 500;
}

.action-hint {
  margin-left: auto;
  font-size: 12px;
  color: var(--text-light);
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.launch-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 14px 24px;
  background: var(--primary);
  color: white;
  border: none;
  border-radius: 10px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s;
  margin-top: 8px;
}

.launch-btn:hover:not(:disabled) {
  background: var(--primary-dark);
}

.launch-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.export-cmd-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 16px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  border-radius: 8px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s;
}

.export-cmd-btn:hover {
  border-color: var(--primary);
  color: var(--primary);
  background: var(--primary-bg);
}

.tip-box {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 10px;
  padding: 8px 12px;
  background: color-mix(in srgb, var(--primary) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--primary) 30%, transparent);
  border-radius: 8px;
  font-size: 12px;
  line-height: 1.5;
  user-select: none;
}

.tip-label {
  flex-shrink: 0;
  padding: 1px 6px;
  background: var(--primary);
  color: #fff;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.5px;
}

.tip-content {
  color: var(--text-secondary);
}

.launch-version {
  font-size: 12px;
  font-weight: 400;
  opacity: 0.85;
  max-width: 100px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.launch-msg {
  text-align: center;
  font-size: 13px;
  margin-top: 4px;
}

.launch-msg.info { color: var(--primary); }
.launch-msg.success { color: var(--success); }
.launch-msg.error { color: var(--danger); }

.launch-msg-glass {
  text-align: center;
  margin-top: 8px;
  padding: 10px 14px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border-radius: 8px;
  border: 1px solid var(--glass-border);
}

.isolation-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 12px;
  padding: 8px 0;
}

.isolation-label {
  font-size: 13px;
  color: var(--text-secondary);
}

/* 右侧面板 */
.right-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  padding: 32px 40px;
  position: relative;
}

.right-glass-container {
  flex: 1;
  padding: 32px 36px;
  border-radius: 16px;
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--glass-border);
  margin: 24px;
  overflow-y: auto;
}

.right-content {
  flex: 1;
}

.welcome-title {
  font-size: 26px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 6px;
}

.welcome-desc {
  font-size: 14px;
  color: var(--text-light);
  margin-bottom: 32px;
}

.feature-cards {
  display: flex;
  gap: 20px;
  flex-wrap: wrap;
}

.feature-card {
  width: 200px;
  padding: 24px 20px;
  background: var(--glass-bg-light);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1.5px solid var(--border);
  border-radius: 12px;
  cursor: pointer;
  transition: all 0.2s;
}

.feature-card:hover {
  border-color: var(--primary);
  box-shadow: 0 4px 16px color-mix(in srgb, var(--primary) 15%, transparent);
}

.feature-icon {
  font-size: 32px;
  margin-bottom: 12px;
}

.feature-name {
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 4px;
}

.feature-desc {
  font-size: 12px;
  color: var(--text-light);
}

.easy-qgl-card {
  border-color: var(--easy-orange, #FF9800);
  background: color-mix(in srgb, var(--easy-orange, #FF9800) 6%, transparent);
}

.easy-qgl-card:hover {
  border-color: var(--easy-orange-dark, #F57C00);
  box-shadow: 0 4px 16px color-mix(in srgb, var(--easy-orange, #FF9800) 20%, transparent);
  background: color-mix(in srgb, var(--easy-orange, #FF9800) 10%, transparent);
}

.qglplus-card {
  border-color: var(--qglplus-green, #4CAF50);
  background: color-mix(in srgb, var(--qglplus-green, #4CAF50) 6%, transparent);
}

.qglplus-card:hover {
  border-color: var(--qglplus-green-dark, #388E3C);
  box-shadow: 0 4px 16px color-mix(in srgb, var(--qglplus-green, #4CAF50) 20%, transparent);
  background: color-mix(in srgb, var(--qglplus-green, #4CAF50) 10%, transparent);
}

.locked-notice {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 40px 20px;
  background: var(--glass-bg-light);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1.5px dashed var(--border);
  border-radius: 12px;
  text-align: center;
}

.locked-icon {
  font-size: 36px;
  margin-bottom: 12px;
}

.locked-text {
  font-size: 15px;
  font-weight: 500;
  color: var(--text-secondary);
  margin-bottom: 4px;
}

.locked-sub {
  font-size: 12px;
  color: var(--text-light);
}

.copyright {
  position: absolute;
  bottom: 16px;
  right: 40px;
  font-size: 11px;
  color: var(--text-light);
}

/* 用户列表 */
.user-list {
  max-height: 300px;
  overflow-y: auto;
}

.user-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.15s;
}

.user-item:hover { background: var(--primary-bg); }
.user-item.active { background: var(--primary-bg); }

.user-avatar {
  width: 40px;
  height: 40px;
  background: var(--primary-light);
  color: var(--primary-dark);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 16px;
  font-weight: 600;
  flex-shrink: 0;
}

.user-name {
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
}

.user-pwd-hint {
  font-size: 12px;
  color: var(--text-light);
}

.current-badge {
  margin-left: auto;
  font-size: 11px;
  padding: 2px 8px;
  background: var(--primary-bg);
  color: var(--primary-dark);
  border-radius: 10px;
  font-weight: 500;
}

/* 版本列表 */
.version-list {
  max-height: 300px;
  overflow-y: auto;
}

.version-item {
  display: flex;
  align-items: center;
  padding: 10px 14px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.15s;
}

.version-item:hover { background: var(--primary-bg); }
.version-item.active { background: var(--primary-bg); }

.version-name {
  font-size: 14px;
  font-weight: 500;
}

.version-loader-tag {
  display: inline-block;
  margin-left: 6px;
  padding: 1px 6px;
  font-size: 11px;
  color: var(--text-light);
  background: var(--bg-secondary);
  border-radius: 4px;
  text-transform: capitalize;
}

.empty-hint {
  text-align: center;
  color: var(--text-light);
  padding: 20px;
  font-size: 14px;
}

.add-user-option {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px;
  margin-top: 8px;
  border-top: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  color: var(--primary-dark);
  font-size: 14px;
  font-weight: 500;
  transition: background 0.15s;
}

.add-user-option:hover { background: var(--primary-bg); }

.add-user-icon {
  width: 32px;
  height: 32px;
  background: var(--primary-bg);
  border: 1.5px dashed var(--primary);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  font-weight: 600;
  color: var(--primary);
}
</style>
