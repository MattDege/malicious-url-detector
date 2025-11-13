import React, { useState } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';
import Sidebar from './components/Sidebar';
import RiskGauge from './components/RiskGauge';
import { scanURL } from './services/api';

function App() {
  const [url, setUrl] = useState('');
  const [currentScan, setCurrentScan] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async () => {
    if (!url) return;

    setLoading(true);
    setError(null);

    try {
      // Call your FastAPI backend
      const result = await scanURL(url);

      // Format the result for display
      const scanResult = {
        url: result.url,
        score: result.risk_assessment.score,
        status: result.risk_assessment.level,
        timestamp: new Date(),
        threats: result.threats.indicators,
        fullData: result // Store complete response
      };

      setCurrentScan(scanResult);
      setRecentScans([scanResult, ...recentScans.slice(0, 9)]);
    } catch (err) {
      setError('Failed to scan URL. Make sure your backend is running on http://localhost:8000');
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="flex">
        {/* Sidebar */}
        <Sidebar recentScans={recentScans} onSelectScan={setCurrentScan} />

        {/* Main Content */}
        <main className="flex-1 p-8">
          {/* Header with Search */}
          <div className="max-w-4xl mx-auto mb-12">
            <div className="text-center mb-8">
              <h1 className="text-4xl font-bold text-gray-900 mb-2">URL Security Scanner</h1>
              <p className="text-gray-600">
                Analyze URLs for potential security threats and malicious content
              </p>
            </div>

            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="url"
                  placeholder="Enter URL to scan (e.g., https://example.com)"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleScan()}
                  className="w-full pl-10 h-12 text-base border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  disabled={loading}
                />
              </div>
              <button
                onClick={handleScan}
                disabled={loading || !url}
                className="px-8 h-12 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed font-medium transition-colors"
              >
                {loading ? 'Scanning...' : 'Scan URL'}
              </button>
            </div>

            {error && (
              <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
                {error}
              </div>
            )}
          </div>

          {/* Results */}
          {currentScan && !loading && (
            <div className="max-w-4xl mx-auto">
              <div className="bg-white border-2 border-gray-200 rounded-lg shadow-sm">
                <div className="text-center p-6 border-b border-gray-200">
                  <h2 className="text-2xl font-bold text-gray-900 mb-2">Scan Results</h2>
                  <p className="font-mono text-base text-gray-600">{currentScan.url}</p>
                </div>

                <div className="p-6">
                  <RiskGauge score={currentScan.score} status={currentScan.status} />

                  {/* Threat Indicators */}
                  {currentScan.threats && currentScan.threats.length > 0 && (
                    <div className="mt-8">
                      <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-gray-900">
                        <AlertTriangle className="h-5 w-5 text-yellow-500" />
                        Detected Threats
                      </h3>
                      <div className="space-y-2">
                        {currentScan.threats.map((threat, index) => (
                          <div
                            key={index}
                            className="flex items-center gap-3 p-3 rounded-lg bg-gray-50 border border-gray-200"
                          >
                            <XCircle className="h-4 w-4 text-red-500 flex-shrink-0" />
                            <span className="text-sm text-gray-800">{threat}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Safe Message */}
                  {currentScan.status === 'SAFE' && (
                    <div className="mt-8 p-4 rounded-lg bg-green-50 border border-green-200">
                      <div className="flex items-center gap-3">
                        <CheckCircle2 className="h-5 w-5 text-green-600" />
                        <div>
                          <p className="font-semibold text-green-800">URL is Safe</p>
                          <p className="text-sm text-green-700">No security threats detected</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Recommendations */}
                  {currentScan.fullData?.recommendations && (
                    <div className="mt-8">
                      <h3 className="text-lg font-semibold mb-4 text-gray-900">Recommendations</h3>
                      <ul className="space-y-2">
                        {currentScan.fullData.recommendations.map((rec, index) => (
                          <li key={index} className="flex items-start gap-2 text-sm text-gray-700">
                            <span className="text-blue-600 mt-1">•</span>
                            <span>{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Empty State */}
          {!currentScan && !loading && (
            <div className="max-w-4xl mx-auto">
              <div className="bg-white border-2 border-dashed border-gray-300 rounded-lg">
                <div className="flex flex-col items-center justify-center py-16">
                  <Shield className="h-16 w-16 text-gray-400 mb-4" />
                  <p className="text-gray-600 text-center">Enter a URL above to begin scanning</p>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;