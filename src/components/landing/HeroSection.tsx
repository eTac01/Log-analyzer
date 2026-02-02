import { motion } from 'framer-motion';
import { Shield, Activity } from 'lucide-react';
import { Suspense } from 'react';
import CyberGlobe from './CyberGlobe';


interface HeroSectionProps {
    onLaunch: () => void;
}

function HeroSection({ onLaunch }: HeroSectionProps) {
    return (
        <div className="relative min-h-screen flex items-center justify-center overflow-hidden">


            <div className="absolute inset-0 z-0">
                <Suspense fallback={<div />}>
                    <CyberGlobe />
                </Suspense>
            </div>

            <div className="absolute inset-0 bg-gradient-to-b from-transparent via-cyber-bg/50 to-cyber-bg z-10" />

            <div className="relative z-20 text-center px-6 max-w-5xl mx-auto">
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, ease: 'easeOut' }}
                    className="mb-6 flex items-center justify-center gap-3"
                >
                    <Shield className="w-12 h-12 text-cyber-primary" strokeWidth={1.5} />
                    <h1 className="font-orbitron text-5xl md:text-7xl font-bold text-cyber-text tracking-wider">
                        CYBER<span className="text-cyber-primary">GUARD</span>
                    </h1>
                </motion.div>

                <motion.h2
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, delay: 0.2, ease: 'easeOut' }}
                    className="font-orbitron text-2xl md:text-4xl font-light text-cyber-text mb-4"
                >
                    Advanced Log Intelligence for Modern SOC Teams
                </motion.h2>

                <motion.p
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, delay: 0.4, ease: 'easeOut' }}
                    className="font-inter text-xl md:text-2xl text-cyber-muted mb-12 tracking-wide"
                >
                    Detect. Correlate. Defend.
                </motion.p>

                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.8, delay: 0.6, ease: 'easeOut' }}
                    className="flex flex-col sm:flex-row gap-4 justify-center items-center"
                >
                    <button
                        onClick={onLaunch}
                        className="group relative px-8 py-4 bg-cyber-primary text-cyber-bg font-orbitron font-bold text-lg rounded-lg overflow-hidden transition-all duration-300 hover:shadow-[0_0_30px_rgba(0,243,255,0.6)] hover:scale-105"
                    >
                        <span className="relative z-10 flex items-center gap-2">
                            <Activity className="w-5 h-5" />
                            Launch Analyzer
                        </span>
                        <div className="absolute inset-0 bg-gradient-to-r from-cyber-primary via-white to-cyber-primary opacity-0 group-hover:opacity-20 transition-opacity duration-300" />
                    </button>

                    <button
                        onClick={() => document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })}
                        className="px-8 py-4 border-2 border-cyber-primary text-cyber-primary font-orbitron font-bold text-lg rounded-lg transition-all duration-300 hover:bg-cyber-primary/10 hover:shadow-[0_0_20px_rgba(0,243,255,0.3)]"
                    >
                        View Capabilities
                    </button>
                </motion.div>

                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 1, delay: 1 }}
                    className="mt-16 grid grid-cols-3 gap-8 max-w-2xl mx-auto"
                >
                    {[
                        { value: '99.9%', label: 'Uptime' },
                        { value: '1M+', label: 'Logs/sec' },
                        { value: '<100ms', label: 'Response' },
                    ].map((stat, index) => (
                        <div key={index} className="text-center">
                            <div className="font-orbitron text-3xl font-bold text-cyber-primary mb-1">
                                {stat.value}
                            </div>
                            <div className="font-inter text-sm text-cyber-muted uppercase tracking-wider">
                                {stat.label}
                            </div>
                        </div>
                    ))}
                </motion.div>
            </div>

            <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-cyber-primary to-transparent opacity-50" />
        </div>
    );
}

export default HeroSection;
