import React, { useState, useEffect } from 'react';
import { X, Server, User, Mail, UserCheck, Check, AlertCircle, RefreshCw } from 'lucide-react';
import { AssetListItem, OwnerOption, apiClient } from '../../api/client';

interface EditAssetModalProps {
  asset: AssetListItem | null;
  isOpen: boolean;
  onClose: () => void;
  availableOwners: OwnerOption[];
  onSaved: (updatedAsset: AssetListItem) => void;
}

export const EditAssetModal: React.FC<EditAssetModalProps> = ({
  asset,
  isOpen,
  onClose,
  availableOwners,
  onSaved,
}) => {
  const [serverName, setServerName] = useState<string>('');
  const [ownerId, setOwnerId] = useState<number>(0);
  const [pocName, setPocName] = useState<string>('');
  const [pocEmail, setPocEmail] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (asset) {
      setServerName(asset.server_name || '');
      setOwnerId(asset.owner_id || 0);
      setPocName(asset.poc_name || '');
      setPocEmail(asset.poc_email || '');
      setErrorMsg(null);
    }
  }, [asset, isOpen]);

  if (!isOpen || !asset) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setErrorMsg(null);

    try {
      const res = await apiClient.patch(`/assets/${asset.id}/owner`, {
        server_name: serverName.trim() || null,
        owner_id: ownerId,
        poc_name: pocName.trim() || null,
        poc_email: pocEmail.trim() || null,
      });

      onSaved(res.data);
      onClose();
    } catch (err: any) {
      setErrorMsg(err.response?.data?.detail || 'Failed to update asset metadata and contact information.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs animate-in fade-in duration-150">
      <div 
        className="w-full max-w-lg bg-surface border border-surfaceBorder rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-surfaceBorder flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">
                Edit Host Assignment & Contact
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                {asset.ip_address} {asset.fqdn ? `• ${asset.fqdn}` : ''}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 overflow-y-auto">
          {errorMsg && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-800 text-red-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Server Name */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Server / Host Name
            </label>
            <input
              type="text"
              value={serverName}
              onChange={(e) => setServerName(e.target.value)}
              placeholder="e.g. bk-appcore-sit, prod-db-01"
              className="w-full bg-slate-950 border border-surfaceBorder rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-sky-500 transition-colors"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Friendly identifier displayed across risk alerts and telemetry reports.
            </p>
          </div>

          {/* Group Ownership */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
              <span>Owner Group (Shared Login Account)</span>
              <span className="text-[10px] text-slate-500 font-normal">Controls access scoping</span>
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <select
                value={ownerId}
                onChange={(e) => setOwnerId(Number(e.target.value))}
                className="w-full bg-slate-950 border border-surfaceBorder rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 transition-colors cursor-pointer"
              >
                <option value={0}>Unassigned (No Owner Group)</option>
                {availableOwners
                  .filter((o) => !o.role || o.role === 'owner')
                  .map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.username} {o.full_name ? `— ${o.full_name}` : ''}
                    </option>
                  ))}
              </select>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              Shared team account (e.g. DB_owner, App_owner, Bakong_owner) used by administrators to manage assets.
            </p>
          </div>

          {/* Point of Contact (PoC) Section */}
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-surfaceBorder space-y-3">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-200">
              <UserCheck className="w-4 h-4 text-indigo-400" />
              <span>Point of Contact (Individual Person)</span>
            </div>
            <p className="text-[11px] text-slate-400">
              Designated person responsible for this asset. Displayed on alert dossiers and in Telegram incident notifications.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              {/* PoC Name */}
              <div>
                <label className="block text-[11px] font-medium text-slate-300 mb-1">
                  PoC Full Name
                </label>
                <div className="relative">
                  <User className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="text"
                    value={pocName}
                    onChange={(e) => setPocName(e.target.value)}
                    placeholder="e.g. Sok Dara"
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 transition-colors"
                  />
                </div>
              </div>

              {/* PoC Email */}
              <div>
                <label className="block text-[11px] font-medium text-slate-300 mb-1">
                  PoC Email Address
                </label>
                <div className="relative">
                  <Mail className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="email"
                    value={pocEmail}
                    onChange={(e) => setPocEmail(e.target.value)}
                    placeholder="e.g. sok.dara@nbc.gov.kh"
                    className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-8 pr-2.5 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-indigo-500 transition-colors"
                  />
                </div>
              </div>
            </div>

            {pocName && pocEmail && (
              <div className="pt-1 flex items-center gap-2 text-[11px] text-indigo-300 font-mono">
                <span className="text-slate-500">Preview:</span>
                <span className="px-2 py-0.5 rounded bg-indigo-950/60 border border-indigo-800/50">
                  {pocName} &lt;{pocEmail}&gt;
                </span>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-surfaceBorder">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-xs font-bold text-white transition-all shadow-md shadow-sky-600/20 disabled:opacity-50 cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <Check className="w-3.5 h-3.5" />
                  <span>Save Assignment</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
