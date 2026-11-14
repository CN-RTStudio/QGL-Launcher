<script setup>
import { ref, onMounted, onUnmounted, computed, nextTick, onErrorCaptured } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  GetServerList, CreateServer, StartServer, StopServer, SendServerCommand,
  GetServerStatus, GetServerLogs, GenerateConnectionCode, ParseConnectionCode,
  DeleteServer, GetVersionManifest
} from '../../wailsjs/go/main/App.js'
import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime.js'
import { showQGLDialog } from '../composables/qglDialog.js'

const props = defineProps({
  currentUser: Object
})

const emit = defineEmits(['navigate'])

const { t } = useI18n()

function cleanError(e) {
  return String(e).replace(/^Error:\s*/, '')
}

// 错误捕获 - 防止生产模式下组件静默渲染为空
const hasError = ref(false)
onErrorCaptured((err) => {
  console.error('QGLPlusPage error:', err)
  hasError.value = true
  return false
})

// 页面状态: 'main' | 'create' | 'manage' | 'join'
const pageState = ref('main')

// 服务器列表
const servers = ref([])
const loading = ref(false)

// 创建服务器表单
const createForm = ref({
  name: '',
  version: '',
  port: 25565,
  maxMemory: 2048,
  minMemory: 1024,
  onlineMode: false,
  customDir: ''
})

// 版本列表
const versionList = ref([])
const versionLoading = ref(false)
const showVersionList = ref(false)

// 服务器管理
const serverStatus = ref({ running: false, ready: false, name: '', port: 0, pid: 0 })
const serverLogs = ref([])
const commandInput = ref('')
const connectionCode = ref('')
const directAddress = ref('')
const logContainer = ref(null)
const selectedServer = ref('')

// 快捷指令
const quickCommands = [
  { label: 'qglplus.cmdOp', cmd: 'op' },
  { label: 'qglplus.cmdDeop', cmd: 'deop' },
  { label: 'qglplus.cmdKick', cmd: 'kick' },
  { label: 'qglplus.cmdBan', cmd: 'ban' },
  { label: 'qglplus.cmdPardon', cmd: 'pardon' },
  { label: 'qglplus.cmdSay', cmd: 'say' },
]
const selectedQuickCmd = ref('')
const showQuickCmdMenu = ref(false)

// 加入服务器
const joinCode = ref('')
const parsedAddress = ref('')

// 创建服务器步骤
const creating = ref(false)
const createStep = ref('')

const isServerMode = computed(() => serverStatus.value.running)

// 加载服务器列表
async function loadServers() {
  loading.value = true
  try {
    const list = await GetServerList()
    servers.value = Array.isArray(list) ? list : []
  } catch (e) {
    console.error('加载服务器列表失败:', e)
    servers.value = []
  }
  loading.value = false
}

// 加载版本列表
async function loadVersions() {
  versionLoading.value = true
  try {
    const manifest = await GetVersionManifest()
    versionList.value = Array.isArray(manifest) ? manifest.filter(v => v && v.type === 'release').map(v => v.id) : []
  } catch (e) {
    console.error('加载版本列表失败:', e)
    versionList.value = []
  }
  versionLoading.value = false
}

// 选择版本
function selectVersion(ver) {
  createForm.value.version = ver
  showVersionList.value = false
}

// 创建服务器（只下载和写配置，不启动）
async function handleCreateServer() {
  if (!createForm.value.name.trim()) {
    showQGLDialog({ title: t('qglplus.error'), content: t('qglplus.nameRequired'), theme: 'error', btn1Label: t('qglplus.close') })
    return
  }
  if (!createForm.value.version) {
    showQGLDialog({ title: t('qglplus.error'), content: t('qglplus.versionRequired'), theme: 'error', btn1Label: t('qglplus.close') })
    return
  }

  creating.value = true
  try {
    createStep.value = 'downloading'
    await CreateServer(
      createForm.value.name,
      createForm.value.version,
      createForm.value.port,
      createForm.value.maxMemory,
      createForm.value.minMemory,
      createForm.value.onlineMode,
      createForm.value.customDir
    )

    createStep.value = ''
    creating.value = false

    pageState.value = 'main'
    await loadServers()

    showQGLDialog({ title: t('qglplus.success'), content: t('qglplus.createServerSuccess'), theme: 'normal', btn1Label: t('qglplus.close') })
  } catch (e) {
    creating.value = false
    createStep.value = ''
    showQGLDialog({ title: t('qglplus.error'), content: t('qglplus.createFailed') + ': ' + cleanError(e), theme: 'error', btn1Label: t('qglplus.close') })
  }
}

// 打开服务器管理
async function openServerManage(name) {
  selectedServer.value = name
  pageState.value = 'manage'
  serverLogs.value = []
  connectionCode.value = ''
  startStatusPolling()
  try {
    const logs = await GetServerLogs()
    serverLogs.value = Array.isArray(logs) ? logs : []
    await nextTick()
    scrollToBottom()
  } catch (e) {
    serverLogs.value = []
  }
}

// 启动服务器
async function handleStartServer() {
  try {
    await StartServer(selectedServer.value)
    startStatusPolling()
  } catch (e) {
    showQGLDialog({ title: t('qglplus.error'), content: cleanError(e), theme: 'error', btn1Label: t('qglplus.close') })
  }
}

// 停止服务器
async function handleStopServer() {
  try {
    await StopServer()
  } catch (e) {
    showQGLDialog({ title: t('qglplus.error'), content: cleanError(e), theme: 'error', btn1Label: t('qglplus.close') })
  }
}

// 发送命令
async function handleSendCommand() {
  if (!commandInput.value.trim()) return
  try {
    let cmd = commandInput.value.trim()
    if (selectedQuickCmd.value) {
      cmd = '/' + selectedQuickCmd.value + ' ' + cmd
    }
    await SendServerCommand(cmd)
    commandInput.value = ''
  } catch (e) {
    showQGLDialog({ title: t('qglplus.error'), content: cleanError(e), theme: 'error', btn1Label: t('qglplus.close') })
  }
}

// 选择快捷指令
function selectQuickCmd(item) {
  if (selectedQuickCmd.value === item.cmd) {
    selectedQuickCmd.value = ''
  } else {
    selectedQuickCmd.value = item.cmd
  }
  showQuickCmdMenu.value = false
}

// 生成连接码
async function handleGenerateCode() {
  try {
    const result = await GenerateConnectionCode(selectedServer.value)
    connectionCode.value = result.code || ''
    directAddress.value = result.directAddr || ''
  } catch (e) {
    showQGLDialog({ title: t('qglplus.error'), content: cleanError(e), theme: 'error', btn1Label: t('qglplus.close') })
  }
}

// 复制到剪贴板
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text)
  } catch (e) {
    const ta = document.createElement('textarea')
    ta.value = text
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  }
}

// 解析连接码
async function handleParseCode() {
  if (!joinCode.value.trim()) return
  try {
    parsedAddress.value = await ParseConnectionCode(joinCode.value.trim())
    await copyToClipboard(parsedAddress.value)
  } catch (e) {
    showQGLDialog({ title: t('qglplus.error'), content: cleanError(e), theme: 'error', btn1Label: t('qglplus.close') })
  }
}

// 删除服务器
async function handleDeleteServer(name) {
  try {
    const result = await showQGLDialog({
      title: t('qglplus.confirmDelete'),
      content: t('qglplus.confirmDeleteMsg', { name }),
      theme: 'error',
      btn1Label: t('qglplus.delete'),
      btn2Label: t('qglplus.cancel')
    })
    if (result === 1) {
      await DeleteServer(name)
      await loadServers()
    }
  } catch (e) {
    // 用户取消或其他错误
  }
}

// 日志滚动到底部
function scrollToBottom() {
  if (logContainer.value) {
    logContainer.value.scrollTop = logContainer.value.scrollHeight
  }
}

// 状态轮询
let statusInterval = null
function startStatusPolling() {
  stopStatusPolling()
  statusInterval = setInterval(async () => {
    try {
      serverStatus.value = await GetServerStatus()
    } catch (e) {}
  }, 2000)
  GetServerStatus().then(s => { serverStatus.value = s || { running: false, ready: false } }).catch(() => {})
}

function stopStatusPolling() {
  if (statusInterval) {
    clearInterval(statusInterval)
    statusInterval = null
  }
}

// 监听日志事件
onMounted(async () => {
  try {
    await loadServers()
  } catch (e) {
    console.error('QGLPlusPage mount error:', e)
  }

  try {
    EventsOn('serverLog', (line) => {
      serverLogs.value.push(line)
      if (serverLogs.value.length > 500) {
        serverLogs.value = serverLogs.value.slice(-500)
      }
      nextTick(scrollToBottom)
    })
  } catch (e) {
    console.error('EventsOn serverLog error:', e)
  }

  try {
    EventsOn('serverStatus', (status) => {
      if (status) serverStatus.value = status
    })
  } catch (e) {
    console.error('EventsOn serverStatus error:', e)
  }
})

onUnmounted(() => {
  stopStatusPolling()
  try { EventsOff('serverLog') } catch (e) {}
  try { EventsOff('serverStatus') } catch (e) {}
})

// 返回主页
function goBack() {
  if (pageState.value === 'manage') {
    stopStatusPolling()
  }
  pageState.value = 'main'
  loadServers()
}
</script>

<template>
  <div class="qglplus-page" :class="{ 'server-mode': isServerMode }">
    <!-- 错误状态 -->
    <div v-if="hasError" class="error-fallback">
      <p>{{ t('qglplus.loadFailed') }}</p>
      <button class="btn btn-outline" @click="emit('navigate', 'main')">{{ t('qglplus.backToMain') }}</button>
    </div>

    <template v-else>
    <!-- 顶部导航 -->
    <div class="page-header">
      <button class="btn btn-outline back-btn" @click="pageState === 'main' ? emit('navigate', 'main') : goBack()">
        ← {{ pageState === 'main' ? t('qglplus.backToMain') : t('qglplus.back') }}
      </button>
      <h1 class="page-title">QGLPlus</h1>
      <span v-if="isServerMode" class="server-mode-badge">{{ t('qglplus.serverMode') }}</span>
    </div>

    <!-- 主页面：我要创建 / 我要加入 -->
    <div v-if="pageState === 'main'" class="main-content">
      <div class="choice-cards">
        <div class="glass-container choice-card create-card" @click="pageState = 'create'; loadVersions()">
          <div class="choice-icon">🚀</div>
          <div class="choice-title">{{ t('qglplus.iWantToCreate') }}</div>
          <div class="choice-desc">{{ t('qglplus.createDesc') }}</div>
        </div>
        <div class="glass-container choice-card join-card" @click="pageState = 'join'">
          <div class="choice-icon">🔗</div>
          <div class="choice-title">{{ t('qglplus.iWantToJoin') }}</div>
          <div class="choice-desc">{{ t('qglplus.joinDesc') }}</div>
        </div>
      </div>

      <!-- 服务器列表 -->
      <div class="glass-container server-list-section">
        <h3>{{ t('qglplus.serverList') }}</h3>
        <div v-if="loading" class="loading-text">{{ t('qglplus.loading') }}</div>
        <div v-else-if="servers.length === 0" class="empty-text">{{ t('qglplus.noServers') }}</div>
        <div v-else class="server-list">
          <div v-for="server in servers" :key="server.name" class="server-item">
            <div class="server-info">
              <div class="server-name">{{ server.name }}</div>
              <div class="server-meta">{{ server.version }} | :{{ server.port }} | {{ server.onlineMode ? t('qglplus.online') : t('qglplus.offline') }}</div>
            </div>
            <div class="server-actions">
              <button class="btn btn-primary btn-sm" @click="openServerManage(server.name)">{{ t('qglplus.manage') }}</button>
              <button class="btn btn-danger btn-sm" @click="handleDeleteServer(server.name)">{{ t('qglplus.deleteBtn') }}</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 创建服务器页面 -->
    <div v-else-if="pageState === 'create'" class="create-content">
      <div v-if="creating" class="creating-overlay">
        <div class="creating-spinner"></div>
        <div class="creating-text">
          <template v-if="createStep === 'downloading'">{{ t('qglplus.downloadingServer') }}</template>
          <template v-else-if="createStep === 'starting'">{{ t('qglplus.startingServer') }}</template>
          <template v-else-if="createStep === 'stopping'">{{ t('qglplus.stoppingServer') }}</template>
          <template v-else-if="createStep === 'setting_online_mode'">{{ t('qglplus.settingOnlineMode') }}</template>
        </div>
      </div>

      <div class="glass-container form-section">
        <h3>{{ t('qglplus.createServer') }}</h3>

        <div class="form-group">
          <label>{{ t('qglplus.serverName') }}</label>
          <input v-model="createForm.name" type="text" class="form-input" :placeholder="t('qglplus.serverNamePlaceholder')" />
        </div>

        <div class="form-group">
          <label>{{ t('qglplus.version') }}</label>
          <div class="version-selector">
            <input v-model="createForm.version" type="text" class="form-input" :placeholder="t('qglplus.versionPlaceholder')" readonly @click="showVersionList = true" />
            <button class="btn btn-outline btn-sm" @click="showVersionList = true; loadVersions()">{{ t('qglplus.selectVersion') }}</button>
          </div>
        </div>

        <div class="form-row">
          <div class="form-group">
            <label>{{ t('qglplus.port') }}</label>
            <input v-model.number="createForm.port" type="number" class="form-input" />
          </div>
          <div class="form-group">
            <label>{{ t('qglplus.maxMemory') }} (MB)</label>
            <input v-model.number="createForm.maxMemory" type="number" class="form-input" />
          </div>
          <div class="form-group">
            <label>{{ t('qglplus.minMemory') }} (MB)</label>
            <input v-model.number="createForm.minMemory" type="number" class="form-input" />
          </div>
        </div>

        <div class="form-group">
          <label class="checkbox-label">
            <input v-model="createForm.onlineMode" type="checkbox" />
            {{ t('qglplus.onlineMode') }}
          </label>
        </div>

        <div class="form-group">
          <label>{{ t('qglplus.serverDirectory') }}</label>
          <input v-model="createForm.customDir" type="text" class="form-input" :placeholder="t('qglplus.serverDirectoryPlaceholder')" />
        </div>

        <button class="btn btn-primary" :disabled="creating" @click="handleCreateServer">
          {{ creating ? t('qglplus.creating') : t('qglplus.createBtn') }}
        </button>
      </div>

      <!-- 版本选择弹窗 -->
      <div v-if="showVersionList" class="version-modal" @click.self="showVersionList = false">
        <div class="glass-container version-modal-content">
          <h3>{{ t('qglplus.selectVersion') }}</h3>
          <div v-if="versionLoading" class="loading-text">{{ t('qglplus.loadingVersions') }}</div>
          <div v-else class="version-list">
            <div v-for="ver in versionList" :key="ver" class="version-item" @click="selectVersion(ver)">
              {{ ver }}
            </div>
          </div>
          <button class="btn btn-outline" @click="showVersionList = false">{{ t('qglplus.close') }}</button>
        </div>
      </div>
    </div>

    <!-- 服务器管理页面 -->
    <div v-else-if="pageState === 'manage'" class="manage-content">
      <div class="glass-container manage-section">
        <div class="manage-header">
          <h3>{{ selectedServer }}</h3>
          <div class="manage-controls">
            <button v-if="!serverStatus.running" class="btn btn-primary" @click="handleStartServer">{{ t('qglplus.startServer') }}</button>
            <button v-else class="btn btn-danger" @click="handleStopServer">{{ t('qglplus.stopServer') }}</button>
            <button v-if="serverStatus.running && !serverStatus.ready" class="btn btn-outline" disabled>{{ t('qglplus.starting') }}...</button>
            <button v-if="serverStatus.running && serverStatus.ready" class="btn btn-outline" @click="handleGenerateCode">{{ t('qglplus.getConnectionCode') }}</button>
          </div>
        </div>

        <!-- 连接码 -->
        <div v-if="connectionCode" class="connection-code-section">
          <label>{{ t('qglplus.connectionCode') }}</label>
          <div class="connection-code-box">
            <code>{{ connectionCode }}</code>
            <button class="btn btn-outline btn-sm" @click="copyToClipboard(connectionCode)">{{ t('qglplus.copy') }}</button>
          </div>
          <div v-if="directAddress" class="direct-address-box">
            <span>{{ t('qglplus.orDirectAddr') }}</span>
            <code>{{ directAddress }}</code>
            <button class="btn btn-outline btn-sm" @click="copyToClipboard(directAddress)">{{ t('qglplus.copy') }}</button>
          </div>
        </div>
      </div>

      <!-- 日志区域 -->
      <div class="glass-container log-section">
        <div class="log-container" ref="logContainer">
          <div v-for="(log, idx) in serverLogs" :key="idx" class="log-line">{{ log }}</div>
          <div v-if="serverLogs.length === 0" class="empty-text">{{ t('qglplus.noLogs') }}</div>
        </div>
        <div class="command-input-section">
          <div class="quick-cmd-wrapper">
            <button
              class="btn btn-outline btn-sm quick-cmd-btn"
              :class="{ active: selectedQuickCmd }"
              :disabled="!serverStatus.running"
              @click="showQuickCmdMenu = !showQuickCmdMenu"
            >
              {{ selectedQuickCmd ? '/' + selectedQuickCmd : t('qglplus.quickCmd') }}
            </button>
            <div v-if="showQuickCmdMenu" class="quick-cmd-menu">
              <div
                v-for="item in quickCommands"
                :key="item.cmd"
                class="quick-cmd-item"
                :class="{ active: selectedQuickCmd === item.cmd }"
                @click="selectQuickCmd(item)"
              >
                {{ t(item.label) }}
              </div>
            </div>
          </div>
          <input
            v-model="commandInput"
            type="text"
            class="form-input command-input"
            :placeholder="selectedQuickCmd ? '/' + selectedQuickCmd + ' ...' : t('qglplus.commandPlaceholder')"
            :disabled="!serverStatus.running"
            @keyup.enter="handleSendCommand"
            @focus="showQuickCmdMenu = false"
          />
          <button class="btn btn-primary btn-sm" :disabled="!serverStatus.running" @click="handleSendCommand">{{ t('qglplus.send') }}</button>
        </div>
      </div>
    </div>

    <!-- 加入服务器页面 -->
    <div v-else-if="pageState === 'join'" class="join-content">
      <div class="glass-container form-section">
        <h3>{{ t('qglplus.joinServer') }}</h3>
        <div class="form-group">
          <label>{{ t('qglplus.connectionCodeInput') }}</label>
          <input v-model="joinCode" type="text" class="form-input" :placeholder="t('qglplus.connectionCodePlaceholder')" />
        </div>
        <button class="btn btn-primary" @click="handleParseCode">{{ t('qglplus.parseCode') }}</button>

        <div v-if="parsedAddress" class="parsed-result">
          <label>{{ t('qglplus.serverAddress') }}</label>
          <div class="address-box">
            <code>{{ parsedAddress }}</code>
            <button class="btn btn-outline btn-sm" @click="copyToClipboard(parsedAddress)">{{ t('qglplus.copy') }}</button>
          </div>
          <p class="join-hint">{{ t('qglplus.joinHint') }}</p>
        </div>
      </div>
    </div>
    </template>
  </div>
</template>

<style scoped>
.qglplus-page {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  background: transparent;
  position: relative;
  z-index: 2;
}

.qglplus-page.server-mode {
  background: color-mix(in srgb, var(--success) 5%, transparent);
}

.error-fallback {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  color: var(--text);
}

/* 毛玻璃容器 */
.glass-container {
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 14px;
}

.page-header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
}

.page-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  flex: 1;
}

.server-mode-badge {
  background: var(--success);
  color: white;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
}

.back-btn {
  padding: 6px 16px;
  font-size: 13px;
}

.main-content {
  flex: 1;
  overflow-y: auto;
  padding: 32px 40px;
}

.create-content,
.manage-content,
.join-content {
  flex: 1;
  overflow-y: auto;
  padding: 32px 40px;
}

/* 选择卡片 */
.choice-cards {
  display: flex;
  gap: 24px;
  margin-bottom: 32px;
  justify-content: center;
}

.choice-card {
  width: 280px;
  padding: 32px 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.2s;
}

.choice-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 16px var(--glass-shadow);
}

.create-card {
  border-color: var(--success);
}

.create-card:hover {
  border-color: var(--success);
  background: color-mix(in srgb, var(--success) 6%, var(--glass-bg));
}

.join-card {
  border-color: var(--primary);
}

.join-card:hover {
  border-color: var(--primary-dark);
  background: color-mix(in srgb, var(--primary) 6%, var(--glass-bg));
}

.choice-icon {
  font-size: 48px;
  margin-bottom: 12px;
}

.choice-title {
  font-size: 20px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 8px;
}

.choice-desc {
  font-size: 14px;
  color: var(--text-secondary);
}

/* 服务器列表 */
.server-list-section {
  margin-top: 16px;
  padding: 20px 24px;
}

.server-list-section h3 {
  font-size: 18px;
  font-weight: 600;
  margin-bottom: 12px;
  color: var(--text);
}

.server-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.server-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  transition: all 0.15s;
}

.server-item:hover {
  border-color: var(--primary);
}

.server-name {
  font-weight: 600;
  color: var(--text);
}

.server-meta {
  font-size: 12px;
  color: var(--text-secondary);
  margin-top: 2px;
}

.server-actions {
  display: flex;
  gap: 8px;
}

/* 表单 */
.form-section {
  max-width: 600px;
  padding: 24px;
}

.form-section h3 {
  font-size: 20px;
  font-weight: 700;
  margin-bottom: 20px;
  color: var(--text);
}

.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 6px;
}

.form-input {
  width: 100%;
  padding: 10px 14px;
  border: 1.5px solid var(--border);
  border-radius: 6px;
  background: var(--glass-bg-heavy);
  color: var(--text);
  font-size: 14px;
  outline: none;
  transition: border-color 0.2s;
  box-sizing: border-box;
}

.form-input:focus {
  border-color: var(--primary);
}

.form-input::placeholder {
  color: var(--text-light);
}

.form-row {
  display: flex;
  gap: 12px;
}

.form-row .form-group {
  flex: 1;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  accent-color: var(--primary);
}

.version-selector {
  display: flex;
  gap: 8px;
}

.version-selector .form-input {
  flex: 1;
}

/* 版本选择弹窗 */
.version-modal {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.version-modal-content {
  padding: 24px;
  width: 400px;
  max-height: 70vh;
  display: flex;
  flex-direction: column;
}

.version-modal-content h3 {
  margin-bottom: 16px;
  color: var(--text);
}

.version-list {
  flex: 1;
  overflow-y: auto;
  margin-bottom: 16px;
  max-height: 400px;
}

.version-item {
  padding: 10px 14px;
  cursor: pointer;
  border-radius: 6px;
  transition: background 0.15s;
  color: var(--text);
}

.version-item:hover {
  background: color-mix(in srgb, var(--success) 10%, var(--glass-bg-light));
}

/* 创建中遮罩 */
.creating-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--overlay);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.creating-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid color-mix(in srgb, var(--success) 30%, transparent);
  border-top-color: var(--success);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin-bottom: 16px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.creating-text {
  color: white;
  font-size: 16px;
  font-weight: 600;
}

/* 服务器管理 */
.manage-section {
  padding: 20px 24px;
  margin-bottom: 16px;
}

.manage-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}

.manage-header h3 {
  font-size: 20px;
  font-weight: 700;
  color: var(--text);
}

.manage-controls {
  display: flex;
  gap: 8px;
  align-items: center;
}

/* 连接码 */
.connection-code-section {
  padding: 12px 16px;
  border: 1px solid var(--success);
  border-radius: 10px;
  background: color-mix(in srgb, var(--success) 6%, var(--glass-bg-light));
}

.connection-code-section label {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 6px;
  display: block;
}

.connection-code-box {
  display: flex;
  align-items: center;
  gap: 12px;
}

.connection-code-box code {
  flex: 1;
  font-size: 18px;
  font-weight: 700;
  color: var(--success);
  letter-spacing: 2px;
}

/* 日志 */
.log-section {
  padding: 16px;
}

.log-container {
  height: 400px;
  overflow-y: auto;
  background: var(--log-bg, #1a1a2e);
  border-radius: 10px;
  padding: 12px;
  font-family: 'Consolas', 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
}

.log-line {
  color: var(--log-text, #e0e0e0);
  white-space: pre-wrap;
  word-break: break-all;
}

.command-input-section {
  display: flex;
  gap: 8px;
  margin-top: 8px;
  align-items: center;
}

.command-input {
  flex: 1;
  font-family: 'Consolas', 'Courier New', monospace;
}

/* 快捷指令 */
.quick-cmd-wrapper {
  position: relative;
  flex-shrink: 0;
}

.quick-cmd-btn {
  white-space: nowrap;
  min-width: 72px;
}

.quick-cmd-btn.active {
  background: var(--primary);
  color: white;
  border-color: var(--primary);
}

.quick-cmd-menu {
  position: absolute;
  bottom: 100%;
  left: 0;
  margin-bottom: 4px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--border);
  border-radius: 10px;
  box-shadow: var(--glass-shadow);
  z-index: 100;
  min-width: 120px;
  overflow: hidden;
}

.quick-cmd-item {
  padding: 8px 14px;
  cursor: pointer;
  font-family: 'Consolas', 'Courier New', monospace;
  font-size: 13px;
  color: var(--text);
  transition: background 0.12s;
}

.quick-cmd-item:hover {
  background: var(--primary-bg);
}

.quick-cmd-item.active {
  color: var(--primary);
  font-weight: 600;
  background: var(--primary-bg);
}

/* 直连地址 */
.direct-address-box {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 8px;
  font-size: 13px;
}

.direct-address-box span {
  color: var(--text-secondary);
  white-space: nowrap;
}

.direct-address-box code {
  font-family: 'Consolas', 'Courier New', monospace;
  font-size: 13px;
  color: var(--primary);
}

/* 加入服务器 */
.parsed-result {
  margin-top: 20px;
  padding: 16px;
  border: 1px solid var(--primary);
  border-radius: 10px;
  background: color-mix(in srgb, var(--primary) 6%, var(--glass-bg-light));
}

.parsed-result label {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 6px;
  display: block;
}

.address-box {
  display: flex;
  align-items: center;
  gap: 12px;
}

.address-box code {
  flex: 1;
  font-size: 18px;
  font-weight: 700;
  color: var(--primary);
}

.join-hint {
  margin-top: 12px;
  font-size: 13px;
  color: var(--text-secondary);
  line-height: 1.5;
}

/* 通用 */
.loading-text, .empty-text {
  color: var(--text-secondary);
  text-align: center;
  padding: 20px;
  font-size: 14px;
}

.btn-danger {
  background: var(--danger);
  color: white;
  border: none;
  padding: 8px 20px;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-danger:hover:not(:disabled) {
  background: var(--danger);
  filter: brightness(0.9);
}

.btn-danger:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-sm {
  padding: 5px 12px;
  font-size: 12px;
}
</style>