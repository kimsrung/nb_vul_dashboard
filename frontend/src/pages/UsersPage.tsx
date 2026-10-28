import React, { useState, useEffect } from 'react';
import {
  Users, UserPlus, Edit2, Trash2, CheckCircle2,
  X, AlertCircle, RefreshCw, ArrowUpDown, ArrowUp, ArrowDown
} from 'lucide-react';
import { UserItem, UserRole, apiClient } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { TablePagination } from '../components/common/TablePagination';

export const UsersPage: React.FC = () => {
  const { username: currentUsername } = useAuth();
  const [users, setUsers] = useState<UserItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Modal states
  const [showAddModal, setShowAddModal] = useState<boolean>(false);
  const [editingUser, setEditingUser] = useState<UserItem | null>(null);
  const [deletingUser, setDeletingUser] = useState<UserItem | null>(null);

  // Form states (Add)
  const [newUsername, setNewUsername] = useState<string>('');
  const [newFullName, setNewFullName] = useState<string>('');
  const [newEmail, setNewEmail] = useState<string>('');
  const [newPassword, setNewPassword] = useState<string>('');
  const [newRole, setNewRole] = useState<UserRole>('owner');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  // Form states (Edit)
  const [editFullName, setEditFullName] = useState<string>('');
  const [editEmail, setEditEmail] = useState<string>('');
  const [editRole, setEditRole] = useState<UserRole>('owner');
  const [editPassword, setEditPassword] = useState<string>('');
  const [editIsActive, setEditIsActive] = useState<boolean>(true);

  // Sorting & Pagination
  const [sortField, setSortField] = useState<string>('id');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
    setCurrentPage(1);
  };

  const sortedUsers = [...users].sort((a, b) => {
    let aVal: any = a[sortField as keyof UserItem];
    let bVal: any = b[sortField as keyof UserItem];

    if (typeof aVal === 'string') {
      aVal = aVal.toLowerCase();
      bVal = (bVal || '').toLowerCase();
    } else if (typeof aVal === 'boolean') {
      aVal = aVal ? 1 : 0;
      bVal = bVal ? 1 : 0;
    }

    if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
    if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
    return 0;
  });

  const totalPages = Math.max(1, Math.ceil(sortedUsers.length / pageSize));
  const paginatedUsers = sortedUsers.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const fetchUsers = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await apiClient.get<UserItem[]>('/auth/users');
      setUsers(res.data);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Failed to load user list');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMsg(null);
    try {
      await apiClient.post('/auth/users', {
        username: newUsername.trim(),
        full_name: newFullName.trim() || null,
        email: newEmail.trim(),
        password: newPassword,
        role: newRole,
      });
      setSuccessMsg(`User ${newUsername} created successfully`);
      setShowAddModal(false);
      // Reset form
      setNewUsername('');
      setNewFullName('');
      setNewEmail('');
      setNewPassword('');
      setNewRole('owner');
      fetchUsers();
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Failed to create user');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOpenEdit = (u: UserItem) => {
    setEditingUser(u);
    setEditFullName(u.full_name || '');
    setEditEmail(u.email);
    setEditRole(u.role);
    setEditPassword('');
    setEditIsActive(u.is_active);
    setErrorMsg(null);
  };

  const handleUpdateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingUser) return;
    setIsSubmitting(true);
    setErrorMsg(null);
    try {
      const payload: any = {
        full_name: editFullName.trim() || null,
        email: editEmail.trim(),
        role: editRole,
        is_active: editIsActive,
      };
      if (editPassword.trim()) {
        payload.password = editPassword.trim();
      }
      await apiClient.patch(`/auth/users/${editingUser.id}`, payload);
      setSuccessMsg(`User ${editingUser.username} updated successfully`);
      setEditingUser(null);
      fetchUsers();
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Failed to update user');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteUser = async () => {
    if (!deletingUser) return;
    setIsSubmitting(true);
    setErrorMsg(null);
    try {
      await apiClient.delete(`/auth/users/${deletingUser.id}`);
      setSuccessMsg(`User ${deletingUser.username} deleted`);
      setDeletingUser(null);
      fetchUsers();
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Failed to delete user');
    } finally {
      setIsSubmitting(false);
    }
  };

  const getRoleBadge = (role: UserRole) => {
    switch (role) {
      case 'admin':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-950 text-purple-300 border border-purple-800">
            👑 Admin
          </span>
        );
      case 'analyst':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
            🛡️ Analyst
          </span>
        );
      case 'owner':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-sky-950 text-sky-300 border border-sky-800">
            💻 Owner
          </span>
        );
      case 'viewer':
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
            👁️ Viewer
          </span>
        );
    }
  };

  return (
    <div className="p-6 max-w-8xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Users className="w-5 h-5 text-indigo-400" /> User Role Management & Access Control
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Manage system operators, assign RBAC privileges, and scope asset ownership auditing.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-primary-600 hover:bg-primary-500 text-xs font-bold text-white shadow-md shadow-primary-600/20"
          >
            <UserPlus className="w-4 h-4" />
            Add New User
          </button>
        </div>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="p-3 rounded-lg bg-red-950/40 border border-red-800 text-red-400 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
          <button onClick={() => setErrorMsg(null)} className="text-red-400 hover:text-red-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {successMsg && (
        <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800 text-emerald-400 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{successMsg}</span>
          </div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-300">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Role Guide Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
        <div className="p-3 rounded-xl bg-purple-950/20 border border-purple-900/40 space-y-1">
          <div className="font-bold text-purple-300 flex items-center gap-1.5">
            👑 Admin
          </div>
          <p className="text-slate-400 text-[11px]">
            Full platform authority: trigger Qualys scans, manage settings, assign owners, add users.
          </p>
        </div>
        <div className="p-3 rounded-xl bg-indigo-950/20 border border-indigo-900/40 space-y-1">
          <div className="font-bold text-indigo-300 flex items-center gap-1.5">
            🛡️ Analyst
          </div>
          <p className="text-slate-400 text-[11px]">
            Security Operations: triage vulnerabilities, assign server owners, resolve security alerts.
          </p>
        </div>
        <div className="p-3 rounded-xl bg-sky-950/20 border border-sky-900/40 space-y-1">
          <div className="font-bold text-sky-300 flex items-center gap-1.5">
            💻 Owner
          </div>
          <p className="text-slate-400 text-[11px]">
            Scoped ownership: only views and remediates vulnerabilities on their assigned servers.
          </p>
        </div>
        <div className="p-3 rounded-xl bg-slate-800/40 border border-slate-700 space-y-1">
          <div className="font-bold text-slate-300 flex items-center gap-1.5">
            👁️ Viewer
          </div>
          <p className="text-slate-400 text-[11px]">
            Audit & Compliance: read-only access to assets, metrics, and KB guidance without edit rights.
          </p>
        </div>
      </div>

      {/* Users Table */}
      <div className="p-4 rounded-xl bg-surface border border-surfaceBorder overflow-hidden space-y-3">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-900/80 text-[11px] uppercase tracking-wider text-slate-400 border-b border-surfaceBorder select-none">
              <tr>
                <th
                  onClick={() => handleSort('username')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>User</span>
                    {sortField === 'username' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('email')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Email</span>
                    {sortField === 'email' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('role')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Role</span>
                    {sortField === 'role' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('assigned_assets_count')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Assigned Assets</span>
                    {sortField === 'assigned_assets_count' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th
                  onClick={() => handleSort('is_active')}
                  className="py-3 px-4 cursor-pointer hover:text-slate-100 transition-colors"
                >
                  <div className="inline-flex items-center gap-1 font-semibold">
                    <span>Account Status</span>
                    {sortField === 'is_active' ? (
                      sortOrder === 'asc' ? <ArrowUp className="w-3 h-3 text-sky-400" /> : <ArrowDown className="w-3 h-3 text-sky-400" />
                    ) : (
                      <ArrowUpDown className="w-3 h-3 text-slate-600 opacity-60" />
                    )}
                  </div>
                </th>
                <th className="py-3 px-4 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surfaceBorder">
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw className="w-4 h-4 animate-spin text-primary-400" />
                      Loading operators...
                    </div>
                  </td>
                </tr>
              ) : paginatedUsers.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-400">
                    No users registered.
                  </td>
                </tr>
              ) : (
                paginatedUsers.map((u) => (
                  <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-100 flex items-center gap-2">
                        <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-sky-400 text-xs">
                          {u.username.substring(0, 2).toUpperCase()}
                        </div>
                        <div>
                          <div>{u.username}</div>
                          {u.full_name && (
                            <div className="text-[11px] text-slate-400 font-normal">{u.full_name}</div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {u.email}
                    </td>
                    <td className="py-3 px-4">
                      {getRoleBadge(u.role)}
                    </td>
                    <td className="py-3 px-4 font-mono">
                      <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                        {u.assigned_assets_count || 0} servers
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {u.is_active ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" /> Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-medium">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-400" /> Inactive
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleOpenEdit(u)}
                          className="p-1.5 rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 transition-colors cursor-pointer"
                          title="Edit User"
                        >
                          <Edit2 className="w-3.5 h-3.5" />
                        </button>
                        {u.username !== currentUsername && (
                          <button
                            onClick={() => setDeletingUser(u)}
                            className="p-1.5 rounded-lg bg-red-950/40 hover:bg-red-900/60 text-red-400 border border-red-900/50 transition-colors"
                            title="Delete User"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <TablePagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalItems={sortedUsers.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
          label="operators"
        />
      </div>

      {/* Modal: Add New User */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-surface border border-surfaceBorder rounded-2xl shadow-2xl p-6 space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-surfaceBorder pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <UserPlus className="w-4 h-4 text-primary-400" /> Create New Operator
              </h3>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateUser} className="space-y-3 text-xs">
              <div>
                <label className="block font-medium text-slate-300 mb-1">Username *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. jdoe"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  placeholder="e.g. John Doe"
                  value={newFullName}
                  onChange={(e) => setNewFullName(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Email *</label>
                <input
                  type="email"
                  required
                  placeholder="john.doe@company.com"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Initial Password *</label>
                <input
                  type="password"
                  required
                  placeholder="••••••••"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Role & Authorization Level *</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value as UserRole)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                >
                  <option value="owner">Owner (Scoped to assigned assets only)</option>
                  <option value="analyst">Analyst (Triage, assign owners, resolve alerts)</option>
                  <option value="admin">Admin (Full administrative & sync authority)</option>
                  <option value="viewer">Viewer (Read-only auditor)</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-surfaceBorder">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-primary-600 hover:bg-primary-500 text-white font-bold shadow-md disabled:opacity-50"
                >
                  {isSubmitting ? 'Creating...' : 'Create Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Edit User */}
      {editingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="w-full max-w-md bg-surface border border-surfaceBorder rounded-2xl shadow-2xl p-6 space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-surfaceBorder pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Edit2 className="w-4 h-4 text-primary-400" /> Edit Operator: {editingUser.username}
              </h3>
              <button onClick={() => setEditingUser(null)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleUpdateUser} className="space-y-3 text-xs">
              <div>
                <label className="block font-medium text-slate-300 mb-1">Full Name</label>
                <input
                  type="text"
                  placeholder="e.g. John Doe"
                  value={editFullName}
                  onChange={(e) => setEditFullName(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={editEmail}
                  onChange={(e) => setEditEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Role</label>
                <select
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value as UserRole)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                >
                  <option value="owner">Owner (Scoped to assigned assets only)</option>
                  <option value="analyst">Analyst (Triage, assign owners, resolve alerts)</option>
                  <option value="admin">Admin (Full administrative & sync authority)</option>
                  <option value="viewer">Viewer (Read-only auditor)</option>
                </select>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Reset Password (leave empty to keep current)</label>
                <input
                  type="password"
                  placeholder="Enter new password or leave blank"
                  value={editPassword}
                  onChange={(e) => setEditPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-slate-100 focus:outline-none focus:border-primary-500"
                />
              </div>

              <div className="pt-1">
                <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                  <input
                    type="checkbox"
                    checked={editIsActive}
                    onChange={(e) => setEditIsActive(e.target.checked)}
                    className="rounded border-slate-700 text-primary-600 focus:ring-0 bg-slate-900"
                  />
                  <span>Account Active (Allowed to sign in)</span>
                </label>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-surfaceBorder">
                <button
                  type="button"
                  onClick={() => setEditingUser(null)}
                  className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 rounded-lg bg-primary-600 hover:bg-primary-500 text-white font-bold shadow-md disabled:opacity-50"
                >
                  {isSubmitting ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Delete Confirmation */}
      {deletingUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="w-full max-w-sm bg-surface border border-red-900/50 rounded-2xl shadow-2xl p-6 space-y-4 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-red-950/60 border border-red-800 flex items-center justify-center text-red-400">
                <Trash2 className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">Delete User Account</h3>
                <p className="text-xs text-slate-400">This action cannot be undone.</p>
              </div>
            </div>

            <p className="text-xs text-slate-300">
              Are you sure you want to permanently delete user <span className="font-bold text-slate-100">{deletingUser.username}</span>?
            </p>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setDeletingUser(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleDeleteUser}
                disabled={isSubmitting}
                className="px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold shadow-md disabled:opacity-50"
              >
                {isSubmitting ? 'Deleting...' : 'Confirm Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
