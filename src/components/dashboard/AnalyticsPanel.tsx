import { BarChart3 } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const data = [
    { name: 'SQL Inj', value: 42 },
    { name: 'XSS', value: 28 },
    { name: 'Brute Force', value: 65 },
    { name: 'Port Scan', value: 31 },
    { name: 'DDoS', value: 19 },
    { name: 'Malware', value: 53 },
];

function AnalyticsPanel() {
    return (
        <div className="bg-gradient-to-br from-[#0f1535] to-[#0a0e27] border border-cyber-primary/20 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-6">
                <BarChart3 className="w-5 h-5 text-cyber-primary" />
                <h2 className="font-orbitron text-xl font-bold text-cyber-text">Threat Distribution</h2>
            </div>

            <ResponsiveContainer width="100%" height={300}>
                <BarChart data={data}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#00f3ff20" />
                    <XAxis
                        dataKey="name"
                        stroke="#9aa4bf"
                        style={{ fontSize: '12px', fontFamily: 'Inter' }}
                    />
                    <YAxis
                        stroke="#9aa4bf"
                        style={{ fontSize: '12px', fontFamily: 'Inter' }}
                    />
                    <Tooltip
                        contentStyle={{
                            backgroundColor: '#0d1230',
                            border: '1px solid #00f3ff40',
                            borderRadius: '8px',
                            color: '#eaeaea',
                        }}
                    />
                    <Bar dataKey="value" fill="#00f3ff" radius={[8, 8, 0, 0]} />
                </BarChart>
            </ResponsiveContainer>
        </div>
    );
}

export default AnalyticsPanel;
