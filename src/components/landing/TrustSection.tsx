import { motion } from 'framer-motion';
import { CheckCircle2, Shield, Server, TrendingUp } from 'lucide-react';

const stats = [
    { value: '10M+', label: 'Logs Processed Daily', icon: TrendingUp },
    { value: '50K+', label: 'Threats Detected', icon: Shield },
    { value: '99.99%', label: 'System Uptime', icon: Server },
    { value: '<50ms', label: 'Average Response', icon: CheckCircle2 },
];

const features = [
    'SOC-Ready Architecture',
    'Enterprise-Scale Performance',
    'Real-Time Threat Intelligence',
    'Zero-Configuration Deployment',
    'Advanced Attack Correlation',
    'Compliance & Audit Trails',
];

function TrustSection() {
    return (
        <section className="py-24 px-6 bg-gradient-to-b from-cyber-bg-secondary to-cyber-bg relative overflow-hidden">
            <div className="absolute inset-0 opacity-5">
                <div className="absolute top-0 left-0 w-96 h-96 bg-cyber-primary rounded-full blur-3xl" />
                <div className="absolute bottom-0 right-0 w-96 h-96 bg-cyber-purple rounded-full blur-3xl" />
            </div>

            <div className="max-w-7xl mx-auto relative z-10">
                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.6 }}
                    className="text-center mb-16"
                >
                    <h2 className="font-orbitron text-4xl md:text-5xl font-bold text-cyber-text mb-4">
                        Built for Security Analysts
                    </h2>
                    <p className="font-inter text-xl text-cyber-muted max-w-2xl mx-auto">
                        Trusted by security teams worldwide for mission-critical operations
                    </p>
                </motion.div>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-16">
                    {stats.map((stat, index) => (
                        <motion.div
                            key={index}
                            initial={{ opacity: 0, scale: 0.9 }}
                            whileInView={{ opacity: 1, scale: 1 }}
                            viewport={{ once: true }}
                            transition={{ duration: 0.5, delay: index * 0.1 }}
                            className="text-center"
                        >
                            <div className="w-16 h-16 mx-auto mb-4 rounded-lg bg-cyber-primary/10 flex items-center justify-center border border-cyber-primary/30">
                                <stat.icon className="w-8 h-8 text-cyber-primary" strokeWidth={1.5} />
                            </div>
                            <div className="font-orbitron text-4xl font-bold text-cyber-primary mb-2">
                                {stat.value}
                            </div>
                            <div className="font-inter text-sm text-cyber-muted uppercase tracking-wider">
                                {stat.label}
                            </div>
                        </motion.div>
                    ))}
                </div>

                <motion.div
                    initial={{ opacity: 0, y: 30 }}
                    whileInView={{ opacity: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.6 }}
                    className="bg-gradient-to-br from-cyber-bg-tertiary to-cyber-bg-secondary border border-cyber-primary/20 rounded-2xl p-8 md:p-12"
                >
                    <div className="text-center mb-8">
                        <h3 className="font-orbitron text-2xl md:text-3xl font-bold text-cyber-text mb-2">
                            Production-Ready Features
                        </h3>
                        <p className="font-inter text-cyber-muted">
                            Everything you need for modern threat detection and response
                        </p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {features.map((feature, index) => (
                            <motion.div
                                key={index}
                                initial={{ opacity: 0, x: -20 }}
                                whileInView={{ opacity: 1, x: 0 }}
                                viewport={{ once: true }}
                                transition={{ duration: 0.4, delay: index * 0.05 }}
                                className="flex items-center gap-3 p-4 rounded-lg bg-cyber-bg-secondary border border-cyber-primary/10 hover:border-cyber-primary/30 transition-colors duration-300"
                            >
                                <CheckCircle2 className="w-5 h-5 text-cyber-green flex-shrink-0" strokeWidth={2} />
                                <span className="font-inter text-cyber-text">{feature}</span>
                            </motion.div>
                        ))}
                    </div>
                </motion.div>
            </div>
        </section>
    );
}

export default TrustSection;
