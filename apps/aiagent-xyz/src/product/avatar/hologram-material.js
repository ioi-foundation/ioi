import { Color, DoubleSide, ShaderMaterial } from 'three';

// The landing figure's etched glass treatment, using the pinned renderer's
// morph and skin chunks for both the surface and its normals.
export function createHologramMaterial(name) {
  const internal = name === 'mechanism';
  const material = new ShaderMaterial({
    name,
    transparent: true,
    depthWrite: false,
    side: DoubleSide,
    uniforms: {
      fill: { value: new Color(internal ? 0xe5e5e3 : 0xf2f2f0) },
      rim: { value: new Color(internal ? 0x111111 : 0x000000) },
      fillOpacity: { value: internal ? .16 : .08 },
      rimOpacity: { value: internal ? .70 : .63 },
      rimPower: { value: internal ? 1.8 : 2.0 },
      time: { value: 0 },
    },
    vertexShader: `
      #include <common>
      #include <morphtarget_pars_vertex>
      #include <skinning_pars_vertex>
      varying vec3 avatarNormal;
      varying vec3 avatarView;
      varying float avatarHeight;
      void main() {
        #include <beginnormal_vertex>
        #include <morphnormal_vertex>
        #include <skinbase_vertex>
        #include <skinnormal_vertex>
        #include <defaultnormal_vertex>
        #include <begin_vertex>
        #include <morphtarget_vertex>
        #include <skinning_vertex>
        #include <project_vertex>
        avatarNormal = normalize(transformedNormal);
        avatarView = -mvPosition.xyz;
        avatarHeight = (modelMatrix * vec4(transformed, 1.0)).y;
      }
    `,
    fragmentShader: `
      uniform vec3 fill;
      uniform vec3 rim;
      uniform float fillOpacity;
      uniform float rimOpacity;
      uniform float rimPower;
      uniform float time;
      varying vec3 avatarNormal;
      varying vec3 avatarView;
      varying float avatarHeight;
      void main() {
        float edge = pow(1.0 - abs(dot(normalize(avatarNormal), normalize(avatarView))), rimPower);
        float scan = .94 + .06 * sin(avatarHeight * 150.0 - time * 2.0);
        gl_FragColor = vec4(mix(fill, rim, edge), clamp((fillOpacity + edge * rimOpacity) * scan, 0.0, 1.0));
        #include <colorspace_fragment>
      }
    `,
  });
  material.color = material.uniforms.fill.value;
  return material;
}
