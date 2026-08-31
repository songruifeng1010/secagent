<template>
  <div style="padding: 20px; height: calc(100vh - 80px); overflow-y: auto;">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
      <div>
        <div style="color: #e2e8f0; font-size: 20px; font-weight: 700;">用户管理</div>
        <div style="color: #64748b; font-size: 13px; margin-top: 4px;">RBAC 角色权限管理</div>
      </div>
      <n-button type="primary" size="small" @click="showCreateModal = true">
        + 创建用户
      </n-button>
    </div>

    <n-card :bordered="true" size="small" style="background: #171923;">
      <n-data-table
        :columns="columns"
        :data="users"
        :bordered="false"
        :loading="loading"
        size="small"
        :row-style="() => ({ background: '#171923', color: '#cbd5e1' })"
      />
    </n-card>

    <!-- 创建用户弹窗 -->
    <n-modal v-model:show="showCreateModal" preset="card" title="创建用户" style="width: 450px;"
      :bordered="true" :mask-closable="false">
      <n-form ref="createFormRef" :model="createForm" :rules="rules">
        <n-form-item label="用户名" path="username">
          <n-input v-model:value="createForm.username" placeholder="字母数字组合" />
        </n-form-item>
        <n-form-item label="密码" path="password">
          <n-input v-model:value="createForm.password" type="password" show-password-on="click" />
        </n-form-item>
        <n-form-item label="显示名称" path="display_name">
          <n-input v-model:value="createForm.display_name" placeholder="选填" />
        </n-form-item>
        <n-form-item label="角色" path="role">
          <n-select v-model:value="createForm.role" :options="roleOptions" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-button @click="showCreateModal = false" style="margin-right:8px;">取消</n-button>
        <n-button type="primary" :loading="submitting" @click="handleCreate">创建</n-button>
      </template>
    </n-modal>

    <!-- 编辑用户弹窗 -->
    <n-modal v-model:show="showEditModal" preset="card" title="编辑用户" style="width: 450px;"
      :bordered="true" :mask-closable="false">
      <n-form ref="editFormRef" :model="editForm">
        <n-form-item label="用户名">
          <n-input :value="editUser?.username" disabled />
        </n-form-item>
        <n-form-item label="当前角色">
          <n-select v-model:value="editForm.role" :options="roleOptions" />
        </n-form-item>
        <n-form-item label="是否启用">
          <n-switch v-model:value="editForm.enabled" />
        </n-form-item>
        <n-form-item label="显示名称">
          <n-input v-model:value="editForm.display_name" />
        </n-form-item>
        <n-form-item label="新密码（留空不修改）">
          <n-input v-model:value="editForm.password" type="password" show-password-on="click" placeholder="留空则不修改" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-button @click="showEditModal = false" style="margin-right:8px;">取消</n-button>
        <n-button type="primary" :loading="submitting" @click="handleUpdate">保存</n-button>
      </template>
    </n-modal>
  </div>
</template>

<script setup>
import { ref, h, onMounted } from 'vue'
import { NTag, NButton, useMessage, useDialog } from 'naive-ui'
import { apiFetch } from '../utils/http.js'

const msg = useMessage()
const dialog = useDialog()
const users = ref([])
const loading = ref(false)
const submitting = ref(false)
const showCreateModal = ref(false)
const showEditModal = ref(false)
const editUser = ref(null)

const roleOptions = [
  { label: 'admin', value: 'admin' },
  { label: 'operator', value: 'operator' },
  { label: 'analyst', value: 'analyst' },
  { label: 'viewer', value: 'viewer' },
]

const createForm = ref({ username: '', password: '', role: 'viewer', display_name: '' })
const editForm = ref({ role: 'viewer', enabled: true, display_name: '', password: '' })

const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  role: [{ required: true, message: '请选择角色', trigger: 'blur' }],
}

const columns = [
  { title: '用户名', key: 'username', width: 140, render: (row) => h('span', { style: 'color:#e2e8f0;font-weight:500;' }, row.username) },
  { title: '显示名称', key: 'display_name', width: 140 },
  {
    title: '角色', key: 'role', width: 100,
    render: (row) => h(NTag, { size: 'small', type: roleTagType(row.role), bordered: false }, () => row.role),
  },
  {
    title: '状态', key: 'enabled', width: 80,
    render: (row) => h(NTag, { size: 'small', type: row.enabled ? 'success' : 'error', bordered: false }, () => row.enabled ? '启用' : '禁用'),
  },
  {
    title: '操作', key: 'actions', width: 180,
    render: (row) => h('div', { style: 'display:flex;gap:8px;' }, [
      h(NButton, { size: 'tiny', quaternary: true, onClick: () => openEdit(row) }, () => '编辑'),
      row.username !== 'admin' ? h(NButton, { size: 'tiny', quaternary: true, type: 'error', onClick: () => confirmDelete(row) }, () => '删除') : null,
    ]),
  },
]

function roleTagType(role) {
  return { admin: 'error', operator: 'warning', analyst: 'info', viewer: 'default' }[role] || 'default'
}

async function fetchUsers() {
  loading.value = true
  try {
    const data = await apiFetch('/api/users')
    users.value = data.users || []
  } catch (e) {
    msg.error('获取用户列表失败')
  } finally {
    loading.value = false
  }
}

async function handleCreate() {
  submitting.value = true
  try {
    await apiFetch('/api/users', {
      method: 'POST',
      body: JSON.stringify(createForm.value),
    })
    msg.success('创建成功')
    showCreateModal.value = false
    createForm.value = { username: '', password: '', role: 'viewer', display_name: '' }
    await fetchUsers()
  } catch (e) {
    msg.error('创建用户失败')
  } finally {
    submitting.value = false
  }
}

function openEdit(user) {
  editUser.value = user
  editForm.value = {
    role: user.role,
    enabled: user.enabled ?? true,
    display_name: user.display_name || '',
    password: '',
  }
  showEditModal.value = true
}

async function handleUpdate() {
  if (!editUser.value) return
  submitting.value = true
  try {
    const body = { role: editForm.value.role, enabled: editForm.value.enabled, display_name: editForm.value.display_name }
    if (editForm.value.password) body.password = editForm.value.password
    await apiFetch(`/api/users/${editUser.value.username}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    })
    msg.success('更新成功')
    showEditModal.value = false
    await fetchUsers()
  } catch (e) {
    msg.error('更新用户失败')
  } finally {
    submitting.value = false
  }
}

function confirmDelete(user) {
  dialog.warning({
    title: '确认删除',
    content: `确定要删除用户 "${user.username}" 吗？此操作不可恢复。`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await apiFetch(`/api/users/${user.username}`, {
          method: 'DELETE',
        })
        msg.success('删除成功')
        await fetchUsers()
      } catch (e) {
        msg.error('删除用户失败')
      }
    },
  })
}

onMounted(fetchUsers)
</script>
