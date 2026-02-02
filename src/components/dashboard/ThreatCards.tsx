import { AlertTriangle, Shield, AlertCircle } from 'lucide-react';

const threats = [
    {
        severity: 'critical',
        type: 'SQL Injection Attempt',
        sourceIP: '192.168.1.101',
        timestamp: '2 min ago',
        confidence: 98,
        color: 'bg-red-500',
        textColor: 'text-red-500',
        icon: AlertTriangle,
    },
    {
        severity: 'high',
        type: 'Brute Force Attack',
        sourceIP: '10.0.0.45',
        timestamp: '5 min ago',
        confidence: 94,
        color: 'bg-orange-500',
        textColor: 'text-orange-500',
        icon: AlertCircle,
    },
    {
        severity: 'medium',
        type: 'Port Scanning Detected',
        sourceIP: '172.16.0.23',
        timestamp: '12 min ago',
        confidence: 87,
        color: 'bg-yellow-500',
        textColor: 'text-yellow-500',
        icon: Shield,
    },
];

function ThreatCards() {
    return (
        <div className="bg-gradient-to-br from-[#0f1535] to-[#0a0e27] border border-cyber-primary/20 rounded-xl p-6">
            <h2 className="font-orbitron text-xl font-bold text-cyber-text mb-4">Active Threats</h2>

            <div className="space-y-4">
                {threats.map((threat, index) => {
                    const Icon = threat.icon;

                    return (
                        <div
                            key={index}
                            className="group bg-cyber-bg-secondary border border-cyber-primary/10 rounded-lg p-4 hover:border-cyber-primary/30 hover:bg-cyber-primary/5 transition-all duration-300 cursor-pointer"
                        >
                            <div className="flex items-start gap-3">
                                <div className={`p-2 rounded-lg ${threat.color} bg-opacity-10`}>
                                    <Icon className={`w-5 h-5 ${threat.textColor}`} />
                                </div>

                                <div className="flex-1">
                                    <div className="flex items-center justify-between mb-2">
                                        <h3 className="font-orbitron font-bold text-cyber-text">{threat.type}</h3>
                                        <span className={`text-xs font-inter px-2 py-1 rounded ${threat.color} bg-opacity-10 ${threat.textColor} uppercase`}>
                                            {threat.severity}
                                        </span>
                                    </div>

                                    <div className="grid grid-cols-3 gap-4 text-sm">
                                        <div>
                                            <p className="text-xs text-cyber-muted">Source IP</p>
                                            <p className="font-fira text-cyber-primary">{threat.sourceIP}</p>
                                        </div>
                                        <div>
                                            <p className="text-xs text-cyber-muted">Time</p>
                                            <p className="text-cyber-text">{threat.timestamp}</p>
                                        </div>
                                        <div>
                                            <p className="text-xs text-cyber-muted">Confidence</p>
                                            <p className="text-cyber-text">{threat.confidence}%</p>
                                        </div>
                                    </div>

                                    <div className="mt-3 h-1 bg-cyber-bg rounded-full overflow-hidden">
                                        <div
                                            className={`h-full ${threat.color} transition-all duration-300`}
                                            style={{ width: `${threat.confidence}%` }}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

export default ThreatCards;
