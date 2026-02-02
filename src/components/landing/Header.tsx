import { useState, useEffect } from 'react';
import { Shield, Sun, Moon } from 'lucide-react';

function Header() {
    const [isDarkMode, setIsDarkMode] = useState(true);

    useEffect(() => {
        const root = document.documentElement;
        if (isDarkMode) {
            root.classList.remove('light-mode');
        } else {
            root.classList.add('light-mode');
        }
    }, [isDarkMode]);

    const toggleTheme = () => {
        setIsDarkMode(!isDarkMode);
    };

    return (
        <header className="fixed top-0 left-0 right-0 z-50 h-20 bg-cyber-bg/80 backdrop-blur-md border-b border-cyber-primary/20 flex items-center justify-between px-6 md:px-12 transition-colors duration-300">
            {/* Logo area */}
            <div className="flex items-center gap-2">
                <Shield className="w-8 h-8 text-cyber-primary" />
                <h1 className="font-orbitron text-2xl font-bold text-cyber-text">
                    CYBER<span className="text-cyber-primary">GUARD</span>
                </h1>
            </div>

            {/* Awesome Pickup Line - Hidden on small screens to avoid clutter */}
            <div className="hidden md:block">
                <p className="font-fira text-cyber-primary text-sm lg:text-base animate-pulse">
                    "Are you a firewall? Because I can't take my eyes off your logs."
                </p>
            </div>

            {/* Theme Toggle Button */}
            <button
                onClick={toggleTheme}
                className="w-12 h-12 rounded-full border-2 border-cyber-primary flex items-center justify-center text-cyber-primary hover:bg-cyber-primary/10 transition-all duration-300 hover:shadow-[0_0_15px_rgba(0,243,255,0.4)] group"
                aria-label="Toggle Day/Night Mode"
            >
                {isDarkMode ? (
                    <Sun className="w-6 h-6 group-hover:rotate-90 transition-transform duration-500" />
                ) : (
                    <Moon className="w-6 h-6 group-hover:-rotate-12 transition-transform duration-500" />
                )}
            </button>
        </header>
    );
}

export default Header;
