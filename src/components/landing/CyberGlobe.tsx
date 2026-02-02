import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Sphere, MeshDistortMaterial } from '@react-three/drei';
import * as THREE from 'three';

function NetworkNodes() {
    const nodesRef = useRef<THREE.Group>(null);

    const nodes = useMemo(() => {
        const temp = [];
        for (let i = 0; i < 50; i++) {
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);
            const radius = 2.5 + Math.random() * 0.5;

            const x = radius * Math.sin(phi) * Math.cos(theta);
            const y = radius * Math.sin(phi) * Math.sin(theta);
            const z = radius * Math.cos(phi);

            temp.push({ position: [x, y, z] as [number, number, number], delay: Math.random() * 2 });
        }
        return temp;
    }, []);

    useFrame(({ clock }) => {
        if (nodesRef.current) {
            nodesRef.current.rotation.y = clock.getElapsedTime() * 0.1;
        }
    });

    return (
        <group ref={nodesRef}>
            {nodes.map((node, i) => (
                <mesh key={i} position={node.position}>
                    <sphereGeometry args={[0.03, 8, 8]} />
                    <meshBasicMaterial color="#00f3ff" />
                    <pointLight color="#00f3ff" intensity={0.5} distance={1} />
                </mesh>
            ))}
        </group>
    );
}

function ConnectionLines() {
    const linesRef = useRef<THREE.Group>(null);

    const lines = useMemo(() => {
        const temp = [];
        for (let i = 0; i < 30; i++) {
            const theta1 = Math.random() * Math.PI * 2;
            const phi1 = Math.acos(2 * Math.random() - 1);
            const theta2 = Math.random() * Math.PI * 2;
            const phi2 = Math.acos(2 * Math.random() - 1);
            const radius = 2.5;

            const start = new THREE.Vector3(
                radius * Math.sin(phi1) * Math.cos(theta1),
                radius * Math.sin(phi1) * Math.sin(theta1),
                radius * Math.cos(phi1)
            );

            const end = new THREE.Vector3(
                radius * Math.sin(phi2) * Math.cos(theta2),
                radius * Math.sin(phi2) * Math.sin(theta2),
                radius * Math.cos(phi2)
            );

            temp.push({ start, end });
        }
        return temp;
    }, []);

    useFrame(({ clock }) => {
        if (linesRef.current) {
            linesRef.current.rotation.y = clock.getElapsedTime() * 0.05;
        }
    });

    return (
        <group ref={linesRef}>
            {lines.map((line, i) => {
                const points = [line.start, line.end];
                const geometry = new THREE.BufferGeometry().setFromPoints(points);

                return (
                    // @ts-ignore
                    <line key={i} geometry={geometry}>
                        <lineBasicMaterial color="#00f3ff" transparent opacity={0.2} />
                    </line>
                );
            })}
        </group>
    );
}

function Globe() {
    const globeRef = useRef<THREE.Mesh>(null);

    useFrame(({ clock }) => {
        if (globeRef.current) {
            globeRef.current.rotation.y = clock.getElapsedTime() * 0.05;
        }
    });

    return (
        <mesh ref={globeRef}>
            <Sphere args={[2.3, 64, 64]}>
                <MeshDistortMaterial
                    color="#0a0e27"
                    attach="material"
                    distort={0.3}
                    speed={1.5}
                    roughness={0.8}
                    metalness={0.5}
                    wireframe
                    wireframeLinewidth={0.5}
                />
            </Sphere>
        </mesh>
    );
}

function ParticleField() {
    const particlesRef = useRef<THREE.Points>(null);

    const particles = useMemo(() => {
        const temp = [];
        for (let i = 0; i < 200; i++) {
            const x = (Math.random() - 0.5) * 10;
            const y = (Math.random() - 0.5) * 10;
            const z = (Math.random() - 0.5) * 10;
            temp.push(x, y, z);
        }
        return new Float32Array(temp);
    }, []);

    useFrame(({ clock }) => {
        if (particlesRef.current) {
            particlesRef.current.rotation.y = clock.getElapsedTime() * 0.02;
            particlesRef.current.rotation.x = clock.getElapsedTime() * 0.01;
        }
    });

    return (
        <points ref={particlesRef}>
            <bufferGeometry>
                <bufferAttribute
                    attach="attributes-position"
                    count={particles.length / 3}
                    array={particles}
                    itemSize={3}
                    args={[particles, 3]}
                />
            </bufferGeometry>
            <pointsMaterial
                size={0.02}
                color="#7f5af0"
                transparent
                opacity={0.6}
                sizeAttenuation
            />
        </points>
    );
}

function CyberGlobe() {
    return (
        <Canvas
            camera={{ position: [0, 0, 8], fov: 50 }}
            style={{ background: 'transparent' }}
        >
            <ambientLight intensity={0.3} />
            <pointLight position={[10, 10, 10]} intensity={0.5} color="#00f3ff" />
            <pointLight position={[-10, -10, -10]} intensity={0.3} color="#7f5af0" />

            <Globe />
            <NetworkNodes />
            <ConnectionLines />
            <ParticleField />

            <OrbitControls
                enableZoom={false}
                enablePan={false}
                autoRotate
                autoRotateSpeed={0.5}
                maxPolarAngle={Math.PI / 1.5}
                minPolarAngle={Math.PI / 3}
            />
        </Canvas>
    );
}

export default CyberGlobe;
