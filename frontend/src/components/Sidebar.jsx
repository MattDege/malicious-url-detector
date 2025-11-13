import React from 'react';
import { Shield } from 'lucide-react';
import ScanCard from './ScanCard';

export default function Sidebar({ recentScans, onSelectScan }) {
  return (
    <aside className="w-80 border-r border-gray-200 bg-white min-h-screen p-6">
      <div className="flex items-center gap-2 mb-8">
        <Shield className="h-6 w-6 text-blue-600" />
        <h2 className="text-lg font-semibold text-gray-800">Recent Scans</h2>
      </div>

      <div className="space-y-3">
        {recentScans.length === 0 ? (
          <div className="text-center text-gray-500 text-sm py-8">
            No recent scans yet
          </div>
        ) : (
          recentScans.map((scan, index) => (
            <ScanCard key={index} scan={scan} onClick={() => onSelectScan(scan)} />
          ))
        )}
      </div>
    </aside>
  );
}