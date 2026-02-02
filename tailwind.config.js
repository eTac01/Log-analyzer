/** @type {import('tailwindcss').Config} */
export default {
    content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
    theme: {
        extend: {
            fontFamily: {
                orbitron: ['Orbitron', 'sans-serif'],
                inter: ['Inter', 'sans-serif'],
                fira: ['Fira Code', 'monospace'],
            },
            colors: {
                cyber: {
                    bg: 'var(--bg-primary)',
                    'bg-secondary': 'var(--bg-secondary)',
                    'bg-tertiary': 'var(--bg-tertiary)',
                    primary: 'var(--primary-color)',
                    purple: '#7f5af0',
                    green: '#00ff9c',
                    text: 'var(--text-primary)',
                    muted: 'var(--text-muted)',
                },
            },
        },
    },
    plugins: [],
};
