import { Network, MapPin, Flag } from 'lucide-react';

const ipData = [
    {
        ip: '192.168.1.101',
        country: 'Russia',
        reputation: 'Malicious',
        score: 95,
        lastSeen: '2 min ago',
        color: 'text-red-500',
    },
    {
        ip: '10.0.0.45',
        country: 'China',
        reputation: 'Suspicious',
        score: 72,
        lastSeen: '5 min ago',
        color: 'text-orange-500',
    },
    {
        ip: '172.16.0.23',
        country: 'United States',
        reputation: 'Unknown',
        score: 45,
        lastSeen: '12 min ago',
        color: 'text-yellow-500',
    },
];

function IPIntelligencePanel() {
    return (
        <div className="bg-gradient-to-br from-[#0f1535] to-[#0a0e27] border border-cyber-primary/20 rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
                <Network className="w-5 h-5 text-cyber-primary" />
                <h2 className="font-orbitron text-xl font-bold text-cyber-text">IP Intelligence</h2>
            </div>

            <div className="space-y-4">
                {ipData.map((item, index) => (
                    <div
                        key={index}
                        className="bg-cyber-bg-secondary border border-cyber-primary/10 rounded-lg p-4 hover:border-cyber-primary/30 transition-colors"
                    >
                        <div className="flex items-center justify-between mb-2">
                            <span className="font-fira text-cyber-primary">{item.ip}</span>
                            <span className={`text-xs font-inter px-2 py-1 rounded bg-opacity-10 ${item.color} uppercase font-medium`}>
                                {item.reputation}
                            </span>
                        </div>

                        <div className="grid grid-cols-2 gap-2 text-sm mb-3">
                            <div className="flex items-center gap-2 text-cyber-muted">
                                <MapPin className="w-4 h-4" />
                                <span>{item.country}</span>
                            </div>
                            <div className="flex items-center gap-2 text-cyber-muted">
                                <Flag className="w-4 h-4" />
                                <span>Score: {item.score}</span>
                            </div>
                        </div>

                        <p className="text-xs text-cyber-muted">Last seen: {item.lastSeen}</p>

                        <div className="mt-2 h-1 bg-cyber-bg rounded-full overflow-hidden">
                            <div
                                className="h-full bg-gradient-to-r from-cyber-primary to-cyber-purple transition-all duration-300"
                                style={{ width: `${item.score}%` }}
                            />
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
}

export default IPIntelligencePanel;
