import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Clock } from 'lucide-react';

export default function ScanCard({ scan, onClick }) {
  const getStatusColor = (status) => {
    switch (status) {
      case 'SAFE':
        return 'text-green-500';
      case 'SUSPICIOUS':
        return 'text-yellow-500';
      case 'MALICIOUS':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  const getBadgeColor = (status) => {
    switch (status) {
      case 'SAFE':
        return 'bg-green-100 text-green-700 border-green-300';
      case 'SUSPICIOUS':
        return 'bg-yellow-100 text-yellow-700 border-yellow-300';
      case 'MALICIOUS':
        return 'bg-red-100 text-red-700 border-red-300';
      default:
        return 'bg-gray-100 text-gray-700 border-gray-300';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'SAFE':
        return <CheckCircle2 className="h-4 w-4" />;
      case 'SUSPICIOUS':
        return <AlertTriangle className="h-4 w-4" />;
      case 'MALICIOUS':
        return <XCircle className="h-4 w-4" />;
      default:
        return null;
    }
  };

  const formatTimestamp = (date) => {
    const now = new Date();
    const diff = Math.floor((now.getTime() - date.getTime()) / 1000 / 60);

    if (diff < 1) return 'Just now';
    if (diff < 60) return `${diff}m ago`;
    if (diff < 1440) return `${Math.floor(diff / 60)}h ago`;
    return `${Math.floor(diff / 1440)}d ago`;
  };

  return (
    <div
      className="bg-white border border-gray-200 rounded-lg p-4 cursor-pointer hover:bg-gray-50 transition-colors"
      onClick={onClick}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <div className={`flex items-center gap-1.5 ${getStatusColor(scan.status)}`}>
          {getStatusIcon(scan.status)}
          <span className="text-xs font-medium uppercase">{scan.status}</span>
        </div>
        <span className="text-xs text-gray-500 flex items-center gap-1">
          <Clock className="h-3 w-3" />
          {formatTimestamp(scan.timestamp)}
        </span>
      </div>
      <p className="text-sm text-gray-800 truncate font-mono mb-2">{scan.url}</p>
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-500">Risk Score</span>
        <span 
          className={`text-sm font-semibold px-2 py-1 rounded border ${getBadgeColor(scan.status)}`}
          style={{ display: 'inline-block' }}
        >
          {scan.score}
        </span>
      </div>
    </div>
  );
}