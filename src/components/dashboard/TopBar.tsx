import { Search, Bell, User } from 'lucide-react';

function TopBar() {
    return (
        <header className="h-16 bg-cyber-bg-secondary border-b border-cyber-primary/20 flex items-center justify-between px-6">
            <div className="flex items-center gap-4 flex-1">
                <div className="relative flex-1 max-w-md">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-cyber-muted" />
                    <input
                        type="text"
                        placeholder="Search logs, IPs, threats..."
                        className="w-full bg-cyber-bg border border-cyber-primary/20 rounded-lg pl-10 pr-4 py-2 text-cyber-text font-inter focus:outline-none focus:border-cyber-primary transition-colors"
                    />
                </div>
            </div>

            <div className="flex items-center gap-4">
                <button className="relative p-2 text-cyber-muted hover:text-cyber-primary transition-colors">
                    <Bell className="w-5 h-5" />
                    <span className="absolute top-1 right-1 w-2 h-2 bg-cyber-primary rounded-full" />
                </button>

                <div className="flex items-center gap-2 px-3 py-2 bg-cyber-bg border border-cyber-primary/20 rounded-lg">
                    <User className="w-5 h-5 text-cyber-primary" />
                    <span className="text-sm font-inter text-cyber-text">Analyst</span>
                </div>
            </div>
        </header>
    );
}

export default TopBar;
