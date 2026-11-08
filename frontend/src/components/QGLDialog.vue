<script setup>
import { ref, computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const visible = ref(false)
const theme = ref('normal') // 'normal' | 'error'
const title = ref('')
const content = ref('')
const btn1Label = ref('')
const btn2Label = ref('')
const btn3Label = ref('')
let _resolve = null

const themeClass = computed(() => `dialog-theme-${theme.value}`)

function show(options) {
  theme.value = options.theme || 'normal'
  title.value = options.title || ''
  content.value = options.content || ''
  btn1Label.value = options.btn1Label || ''
  btn2Label.value = options.btn2Label || ''
  btn3Label.value = options.btn3Label || ''
  visible.value = true

  return new Promise((resolve) => {
    _resolve = resolve
  })
}

function handleBtn(index) {
  visible.value = false
  if (_resolve) {
    _resolve(index)
    _resolve = null
  }
}

function handleOverlayClick() {
  // 点击遮罩不关闭，必须点按钮
}

function copyContent() {
  if (navigator.clipboard && content.value) {
    navigator.clipboard.writeText(content.value)
  }
}

defineExpose({ show })
</script>

<template>
  <Transition name="dialog-fade">
    <div v-if="visible" class="qgl-dialog-overlay" @click="handleOverlayClick">
      <div class="qgl-dialog fade-in" :class="themeClass" @click.stop>
        <!-- 标题栏 -->
        <div class="dialog-header">
          <div class="dialog-title-bar" :class="themeClass">
            <span class="dialog-title-icon" v-if="theme === 'error'">&#x26A0;</span>
            <span class="dialog-title-icon" v-else>&#x2139;</span>
            <span class="dialog-title-text">{{ title }}</span>
          </div>
        </div>

        <!-- 内容区域 -->
        <div class="dialog-body">
          <div class="dialog-content-box" @click="copyContent" :title="t('dialog.clickToCopy')">
            <pre class="dialog-content-text">{{ content }}</pre>
            <div class="copy-hint">{{ t('dialog.clickToCopy') }}</div>
          </div>
        </div>

        <!-- 按钮区域 -->
        <div class="dialog-footer">
          <button
            v-if="btn3Label"
            class="dialog-btn dialog-btn-secondary"
            @click="handleBtn(3)"
          >
            {{ btn3Label }}
          </button>
          <button
            v-if="btn2Label"
            class="dialog-btn dialog-btn-secondary"
            @click="handleBtn(2)"
          >
            {{ btn2Label }}
          </button>
          <button
            v-if="btn1Label"
            class="dialog-btn dialog-btn-primary"
            :class="themeClass"
            @click="handleBtn(1)"
          >
            {{ btn1Label }}
          </button>
        </div>
      </div>
    </div>
  </Transition>
</template>

<style scoped>
.qgl-dialog-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--overlay);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
}

.qgl-dialog {
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(24px);
  -webkit-backdrop-filter: blur(24px);
  border-radius: 16px;
  min-width: 420px;
  max-width: 680px;
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  box-shadow: var(--glass-shadow);
  overflow: hidden;
}

.dialog-header {
  padding: 20px 24px 0;
}

.dialog-title-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  padding-bottom: 16px;
  border-bottom: 2px solid var(--border);
}

.dialog-title-bar.dialog-theme-normal {
  border-bottom-color: var(--primary);
}

.dialog-title-bar.dialog-theme-error {
  border-bottom-color: var(--danger);
}

.dialog-title-icon {
  font-size: 20px;
  flex-shrink: 0;
}

.dialog-title-bar.dialog-theme-normal .dialog-title-icon {
  color: var(--primary);
}

.dialog-title-bar.dialog-theme-error .dialog-title-icon {
  color: var(--danger);
}

.dialog-title-text {
  font-size: 17px;
  font-weight: 700;
  color: var(--text);
}

.dialog-body {
  padding: 20px 24px;
  overflow-y: auto;
  flex: 1;
}

.dialog-content-box {
  background: var(--glass-bg-light);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 14px 16px;
  cursor: pointer;
  transition: border-color 0.15s;
  position: relative;
}

.dialog-content-box:hover {
  border-color: var(--primary);
}

.dialog-content-text {
  font-family: 'Consolas', 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-all;
  margin: 0;
  max-height: 320px;
  overflow-y: auto;
}

.copy-hint {
  text-align: right;
  font-size: 11px;
  color: var(--text-light);
  margin-top: 8px;
  opacity: 0;
  transition: opacity 0.15s;
}

.dialog-content-box:hover .copy-hint {
  opacity: 1;
}

.dialog-footer {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  padding: 16px 24px;
  border-top: 1px solid var(--border);
}

.dialog-btn {
  padding: 8px 20px;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s;
  border: 1px solid transparent;
}

.dialog-btn-secondary {
  background: var(--glass-bg);
  border-color: var(--border);
  color: var(--text);
}

.dialog-btn-secondary:hover {
  border-color: var(--primary);
  background: var(--primary-bg);
}

.dialog-btn-primary {
  color: white;
  border: none;
}

.dialog-btn-primary.dialog-theme-normal {
  background: var(--primary);
}

.dialog-btn-primary.dialog-theme-normal:hover {
  filter: brightness(0.9);
}

.dialog-btn-primary.dialog-theme-error {
  background: var(--danger);
}

.dialog-btn-primary.dialog-theme-error:hover {
  filter: brightness(0.9);
}

/* 过渡动画 */
.dialog-fade-enter-active,
.dialog-fade-leave-active {
  transition: opacity 0.2s ease;
}

.dialog-fade-enter-from,
.dialog-fade-leave-to {
  opacity: 0;
}

.fade-in {
  animation: fadeIn 0.2s ease;
}

@keyframes fadeIn {
  from { opacity: 0; transform: scale(0.95); }
  to { opacity: 1; transform: scale(1); }
}
</style>
