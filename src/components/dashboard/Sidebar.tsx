import { LayoutDashboard, Upload, Shield, Network, Clock, FileText, Settings } from 'lucide-react';

interface SidebarProps {
    activeView: string;
    setActiveView: (view: string) => void;
}

const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'upload', label: 'Upload Logs', icon: Upload },
    { id: 'threats', label: 'Threat Analysis', icon: Shield },
    { id: 'intelligence', label: 'IP Intelligence', icon: Network },
    { id: 'timeline', label: 'Timeline View', icon: Clock },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
];

function Sidebar({ activeView, setActiveView }: SidebarProps) {
    return (
        <aside className="w-64 bg-cyber-bg-secondary border-r border-cyber-primary/20 flex flex-col">
            <div className="p-6 border-b border-cyber-primary/20">
                <div className="flex items-center gap-2 mb-1">
                    <Shield className="w-8 h-8 text-cyber-primary" />
                    <h1 className="font-orbitron text-2xl font-bold text-cyber-text">
                        CYBER<span className="text-cyber-primary">GUARD</span>
                    </h1>
                </div>
                <p className="text-xs text-cyber-muted font-inter">SOC Analytics Platform</p>
            </div>

            <nav className="flex-1 p-4">
                <div className="space-y-1">
                    {navItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = activeView === item.id;

                        return (
                            <button
                                key={item.id}
                                onClick={() => setActiveView(item.id)}
                                className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg font-inter font-medium transition-all duration-200 ${isActive
                                    ? 'bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/30'
                                    : 'text-cyber-muted hover:bg-cyber-primary/5 hover:text-cyber-text'
                                    }`}
                            >
                                <Icon className="w-5 h-5" strokeWidth={1.5} />
                                <span>{item.label}</span>
                            </button>
                        );
                    })}
                </div>
            </nav>

            <div className="p-4 border-t border-cyber-primary/20">
                <div className="flex items-center gap-3 px-4 py-3 bg-cyber-primary/5 rounded-lg border border-cyber-primary/20">
                    <div className="w-2 h-2 bg-cyber-green rounded-full animate-pulse" />
                    <div className="flex-1">
                        <p className="text-xs font-inter text-cyber-text font-medium">System Status</p>
                        <p className="text-xs text-cyber-green">All Systems Operational</p>
                    </div>
                </div>
            </div>
        </aside>
    );
}

export default Sidebar;
