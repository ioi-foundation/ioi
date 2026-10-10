"""Fit a lined performance coat and boots to the licensed VRM 1 sample.

Preserves the authored face, expressions, humanoid mapping, and hair chains.
The source blend and garment controls remain editable. Rebuild from the
unmodified imported source so repeated runs never compound mesh changes.
"""
import bpy, addon_utils, bmesh, math, json
from pathlib import Path
from mathutils import Vector

APP=Path(__file__).resolve().parents[2]
TOOLS=Path.home()/'.local/share/aiagent-tools'
bpy.ops.wm.read_factory_settings(use_empty=True)
bpy.context.preferences.filepaths.save_version=0
bpy.ops.preferences.extension_repo_add(name='Avatar authoring',type='LOCAL',use_custom_directory=True,
    custom_directory=str(TOOLS/'blender-extensions'))
package='bl_ext.'+bpy.context.preferences.extensions.repos[-1].module+'.vrm'
addon_utils.enable(package,default_set=True)
bpy.ops.import_scene.vrm(filepath=str(APP/'assets/avatars/source-models/anime-base-v1.vrm'))
rig=next(o for o in bpy.data.objects if o.type=='ARMATURE')
body=bpy.data.objects['Body']

def material(name,color,shade=None):
    m=bpy.data.materials.new(name);m.use_nodes=True
    m.diffuse_color=(*color,1)
    p=m.node_tree.nodes.get('Principled BSDF');p.inputs['Base Color'].default_value=(*color,1);p.inputs['Roughness'].default_value=.8
    ext=m.vrm_addon_extension.mtoon1
    ext.enabled=True
    ext.pbr_metallic_roughness.base_color_factor=(*color,1)
    ext.extensions.vrmc_materials_mtoon.shade_color_factor=shade or tuple(c*.73 for c in color)
    ext.extensions.vrmc_materials_mtoon.outline_width_mode='worldCoordinates'
    # Thin trim/lining share surfaces; the small underdress pleats also make
    # extruded outlines chatter at phone size. Their silhouette and color
    # separation remain readable without an additional outline pass.
    ext.extensions.vrmc_materials_mtoon.outline_width_factor=0 if name in ['coat-lining','coat-piping','dress'] else .0013
    ext.extensions.vrmc_materials_mtoon.outline_color_factor=(.24,.10,.11)
    ext.double_sided=True
    return m

coatmat=material('coat',(.98,.76,.65),(.78,.46,.35))
lining=material('coat-lining',(.88,.50,.34),(.73,.37,.27))
trim=material('coat-piping',(.33,.13,.14),(.23,.07,.10))
red=material('dress',(.72,.035,.035),(.43,.01,.02))
tights=material('trousers',(.18,.055,.075),(.11,.025,.05))
bootmat=material('boots',(.87,.60,.39),(.69,.39,.29))
solemat=material('sole',(.25,.07,.09),(.14,.035,.04))

def bind(obj,weights):
    obj.parent=rig
    obj.vertex_groups.clear()
    for index,entry in enumerate(weights):
        for name,weight in entry.items():
            if weight<=.0001:continue
            group=obj.vertex_groups.get(name) or obj.vertex_groups.new(name=name)
            group.add([index],weight,'REPLACE')
    for mod in list(obj.modifiers):obj.modifiers.remove(mod)
    mod=obj.modifiers.new('Deformation','ARMATURE');mod.object=rig

def mesh(name,verts,faces,mat,weights,solid=0):
    data=bpy.data.meshes.new(name);data.from_pydata(verts,[],faces);data.update()
    obj=bpy.data.objects.new(name,data);bpy.context.collection.objects.link(obj)
    obj.data.materials.append(mat)
    for p in data.polygons:p.use_smooth=True
    bind(obj,weights)
    if solid:
        s=obj.modifiers.new('Fabric thickness','SOLIDIFY');s.thickness=solid;s.offset=0
    return obj

def strip(name,points,width,mat,weights):
    verts=[];faces=[];vweights=[]
    for i,p in enumerate(points):
        tangent=Vector(points[min(i+1,len(points)-1)])-Vector(points[max(0,i-1)])
        normal=Vector((p[0],p[1],0)).normalized()
        across=tangent.cross(normal).normalized()*width/2
        for sign in [-1,1]: verts.append(Vector(p)+sign*across);vweights.append(weights[i])
        if i:faces.append((i*2-2,i*2-1,i*2+1,i*2))
    return mesh(name,verts,faces,mat,vweights,.001)

# Sixteen independent gores, each with an upper and lower control. Their local
# axes follow the rig; the browser's baked tracks never need a cloth solver.
bpy.context.view_layer.objects.active=rig
bpy.ops.object.mode_set(mode='EDIT')
for j in range(16):
    angle=(j+.5)*math.tau/16
    for level,z in [('upper',1.02),('lower',.71)]:
        b=rig.data.edit_bones.new(f'coat_{j}_{level}')
        b.head=(math.sin(angle)*(.115 if level=='upper' else .278),-math.cos(angle)*(.085 if level=='upper' else .175),z)
        b.tail=(b.head.x,b.head.y,z-.30)
        b.parent=rig.data.edit_bones['J_Bip_C_Hips'] if level=='upper' else rig.data.edit_bones[f'coat_{j}_upper']
bpy.ops.object.mode_set(mode='OBJECT')

def coat_weights(p):
    z=p[2]
    if z>=1.05:
        t=max(0,min(1,(z-1.08)/.16))
        return {'J_Bip_C_Chest':1-t,'J_Bip_C_UpperChest':t}
    angle=math.atan2(p[0],-p[1])%math.tau
    a=(angle/math.tau*16-.5)%16;left=math.floor(a);fraction=a-left
    hips=max(0,min(1,(z-.94)/.11));lower=max(0,min(1,(.81-z)/.25))
    weights={'J_Bip_C_Hips':hips}
    lower=lower*lower*(3-2*lower)
    for j,w in [(left,1-fraction),((left+1)%16,fraction)]:
        weights[f'coat_{j}_upper']=(1-hips)*w*(1-lower)
        weights[f'coat_{j}_lower']=(1-hips)*w*lower
    return weights

def torso_weights(p):
    z=p[2];t=max(0,min(1,(z-1.05)/.18))
    return {'J_Bip_C_Chest':1-t,'J_Bip_C_UpperChest':t}

# Remove the original T-shirt and trainers; retain the original face/hair and
# the hands/neck. Covered skin is masked in this compatible wardrobe preset.
bm=bmesh.new();bm.from_mesh(body.data)
remove=[]
for f in bm.faces:
    name=body.data.materials[f.material_index].name
    p=f.calc_center_median()
    if name in ['Tops_01_CLOTH','Shoes_01_CLOTH','Bottoms_01_CLOTH'] or (name=='Body_00_SKIN' and p.z<1.30 and abs(p.x)<.53):remove.append(f)
bmesh.ops.delete(bm,geom=remove,context='FACES');bm.to_mesh(body.data);bm.free()
# The authored opaque dress replaces the old shorts. Retaining both makes
# their independently deformed hems cross during the extended kick.

# Tailored torso with an open front, fitted waist, and flared, paneled hem.
rows=[(1.325,.051,.044,.027),(1.30,.095,.073,.02),(1.265,.155,.103,.015),
      (1.23,.151,.122,-.006),(1.18,.145,.132,-.013),(1.12,.123,.107,-.006),
      (1.06,.110,.088,0),(1.02,.119,.095,0),(.94,.157,.120,0),
      (.84,.215,.146,0),(.72,.278,.175,.008),(.59,.322,.202,.014),(.45,.355,.221,.021)]
verts=[];weights=[];faces=[];columns=65
for row,(z,rx,ry,cy) in enumerate(rows):
    # Leave an actual layer of air around the fitted red garment. The coat
    # keeps this clearance as the inner hem follows the raised thigh.
    ry+=.018*max(0,min(1,(1-z)/.16))
    # Keep the neckline open, close at the belt, and split again for the kick.
    gap=.24 if z>1.17 else .045 if z>.97 else .12
    for col in range(columns):
        a=gap+(math.tau-2*gap)*col/(columns-1)
        ripple=max(0,(1.01-z))*.016*math.cos(a*8)
        p=(math.sin(a)*(rx+ripple),cy-math.cos(a)*(ry+ripple),z)
        verts.append(p);weights.append(coat_weights(p))
        if row and col:
            k=row*columns+col;faces.append((k-1,k,k-columns,k-columns-1))
coat=mesh('Performance coat',verts,faces,coatmat,weights,.004)
coat.data.materials.append(lining);coat.modifiers['Fabric thickness'].material_offset=1
smooth=coat.modifiers.new('Tailored curvature','SUBSURF');smooth.levels=1;smooth.render_levels=1
bpy.context.view_layer.objects.active=coat
bpy.ops.object.modifier_move_up(modifier=smooth.name)
for col in [0,8,17,32,47,56,64]:
    points=[]
    for r in range(len(rows)):
        p=Vector(verts[r*columns+col]);normal=Vector((p.x,p.y-rows[r][3],0)).normalized()
        points.append(p+normal*.0045)
    seam=strip('Coat seam '+str(col),points,.004,trim,[weights[r*columns+col] for r in range(len(rows))])
    curve=seam.modifiers.new('Seam curvature','SUBSURF');curve.levels=2;curve.render_levels=2
    bpy.context.view_layer.objects.active=seam;bpy.ops.object.modifier_move_up(modifier=curve.name)

# Collar facings, belt, and metal clasps give the garment a readable silhouette.
for side in [-1,1]:
    points=[(side*.045,-.045,1.326),(side*.104,-.074,1.296),(side*.071,-.128,1.244),(side*.036,-.142,1.17),(side*.013,-.116,1.12)]
    shape=[points[0],points[1],points[2],points[3],points[4],(side*.018,-.068,1.30)]
    mesh('Notched collar',shape,[(0,1,2,3,4,5)],coatmat,[torso_weights(p) for p in shape],.004)
points=[(.122*math.sin(a),-.098*math.cos(a)-.002,1.022) for a in [i*math.tau/64 for i in range(65)]]
strip('Waist belt',points,.018,trim,[{'J_Bip_C_Hips':1} for _ in points])

for side,letter in [(1,'L'),(-1,'R')]:
    upper='J_Bip_'+letter+'_UpperArm';lower='J_Bip_'+letter+'_LowerArm';hand='J_Bip_'+letter+'_Hand'
    shoulder=rig.data.bones[upper].head_local;elbow=rig.data.bones[lower].head_local;wrist=rig.data.bones[hand].head_local
    sleeveverts=[];sleeveweights=[];sleevefaces=[];n=24
    for r in range(13):
        t=r/12;p=shoulder.lerp(wrist,t)
        radius=.058*(1-t)+.031*t+.005*math.sin(t*math.pi)
        blend=max(0,min(1,(t-.38)/.25))
        for k in range(n):
            a=k*math.tau/n
            sleeveverts.append(p+Vector((0,math.sin(a)*radius,math.cos(a)*radius)))
            sleeveweights.append({upper:1-blend,lower:blend})
            if r:
                q=r*n+k;prev=r*n+(k-1)%n
                face=(q-n,prev-n,prev,q)
                sleevefaces.append(face if side==1 else tuple(reversed(face)))
    sleeve=mesh('Coat sleeve '+letter,sleeveverts,sleevefaces,coatmat,sleeveweights,.004)
    smooth=sleeve.modifiers.new('Sleeve curvature','SUBSURF');smooth.levels=1;smooth.render_levels=1
    bpy.context.view_layer.objects.active=sleeve;bpy.ops.object.modifier_move_up(modifier=smooth.name)
    for r in [11,12]:
        pts=[sleeveverts[r*n+k%n] for k in range(n+1)]
        strip('Cuff '+letter+str(r),pts,.005,trim,[{lower:1} for _ in pts])

    thigh='J_Bip_'+letter+'_UpperLeg';shin='J_Bip_'+letter+'_LowerLeg';foot='J_Bip_'+letter+'_Foot'
    hip=rig.data.bones[thigh].head_local;knee=rig.data.bones[shin].head_local;ankle=rig.data.bones[foot].head_local
    # Fitted hosiery and a softly folded boot shaft use actual limb centers.
    for kind,top,bottom,mat in [('stocking',.86,.12,tights),('boot',.35,.065,bootmat)]:
        vs=[];ws=[];fs=[]
        for r in range(16):
            z=top+(bottom-top)*r/15
            if z>=knee.z:p=hip.lerp(knee,(hip.z-z)/(hip.z-knee.z))
            else:p=knee.lerp(ankle,(knee.z-z)/(knee.z-ankle.z))
            p.z=z
            if kind=='stocking':radius=.036+.039*max(0,min(1,(z-.38)/.48))
            else:radius=.053+.014*(z-.065)/.285+.002*math.sin(z*80)
            blend=max(0,min(1,(knee.z+.065-z)/.13))
            for k in range(n):
                a=k*math.tau/n;vs.append(p+Vector((math.cos(a)*radius,math.sin(a)*radius,0)))
                ws.append({thigh:1-blend,shin:blend} if kind=='stocking' else {shin:1})
                if r:
                    q=r*n+k;pr=r*n+(k-1)%n;fs.append((q-n,pr-n,pr,q))
        mesh(kind+' '+letter,vs,fs,mat,ws,.003 if kind=='boot' else 0)
    # Sculpted toe box and contrasting outsole, elongated for a clear kick.
    for kind,levels,mat in [('upper',[(.027,.051,.116,-.036),(.045,.058,.126,-.036),(.070,.054,.114,-.025),(.11,.045,.067,.009)],bootmat),
                            ('sole',[(.008,.052,.119,-.038),(.016,.061,.132,-.038),(.03,.059,.13,-.037)],solemat)]:
        vs=[];ws=[];fs=[]
        for r,(z,rx,ry,cy) in enumerate(levels):
            for k in range(32):
                a=k*math.tau/32;vs.append((ankle.x+math.sin(a)*rx,cy-math.cos(a)*ry,z));ws.append({foot:1})
                if r:
                    q=r*32+k;pr=r*32+(k-1)%32;fs.append((q,pr,pr-32,q-32))
        fs.append(tuple(reversed(range(32))))
        mesh('Boot '+kind+' '+letter,vs,fs,mat,ws)

# Short pleated underdress with front/back vents. Joining hem vertices with
# opposite thigh bindings stretched the narrow center faces into spikes during
# the split entrance. Each side now has its own coincident vent edge: the waist
# stays joined visually while the pleats can separate with the legs.
vs=[];ws=[];fs=[];n=61
for side,letter in [(0,'L'),(1,'R')]:
    start=len(vs)
    for row in range(7):
        t=row/6;z=1.018-.225*t
        for k in range(n):
            a=(side+k/(n-1))*math.pi;fold=math.cos(a*20)*.006*t
            p=((.108+.050*t+fold)*math.sin(a),-(.088+.045*t+fold)*math.cos(a),z)
            influence=max(0,min(1,(t-.08)/.72));influence=influence*influence*(3-2*influence)
            vs.append(p);ws.append({'J_Bip_C_Hips':1-influence,'J_Bip_'+letter+'_UpperLeg':influence})
            if row and k:
                q=start+row*n+k;fs.append((q-n,q-n-1,q-1,q))
# MToon already renders both sides. A second 2 mm inner shell lets its outline
# protrude through the front after mobile simplification, causing dark specks.
mesh('Pleated underdress',vs,fs,red,ws)

# A fitted hairband follows the authored scalp rather than floating above it.
vs=[];ws=[];fs=[]
for k in range(49):
    a=math.pi*k/48
    for depth in [-.037,-.025]:
        vs.append((.102*math.cos(a),depth,1.486+.117*math.sin(a)));ws.append({'J_Bip_C_Head':1})
    if k:fs.append((2*k-2,2*k-1,2*k+1,2*k))
mesh('Hairband',vs,fs,bootmat,ws,.002)

# Consolidate compatible garment pieces after baking their authoring modifiers.
# Preserve useful wardrobe boundaries and the face/hair expression meshes.
groups={
    'Performance outerwear':lambda n:n.startswith(('Performance coat','Coat seam','Coat sleeve','Cuff','Notched collar','Waist belt')),
    'Performance footwear':lambda n:n.startswith(('boot ','Boot ')),
    'Performance stockings':lambda n:n.startswith('stocking '),
}
for name,matches in groups.items():
    objects=[obj for obj in bpy.context.scene.objects if obj.type=='MESH' and matches(obj.name)]
    for obj in objects:
        bpy.context.view_layer.objects.active=obj
        armatures=[mod for mod in obj.modifiers if mod.type=='ARMATURE']
        for mod in armatures:mod.show_viewport=False
        for mod in list(obj.modifiers):
            if mod.type!='ARMATURE':bpy.ops.object.modifier_apply(modifier=mod.name)
        for mod in armatures:mod.show_viewport=True
    bpy.ops.object.select_all(action='DESELECT')
    for obj in objects:obj.select_set(True)
    bpy.context.view_layer.objects.active=objects[0]
    bpy.ops.object.join()
    bpy.context.object.name=name

rig['wardrobe']='performance-coat-v1'
rig['coatControls']=json.dumps([f'coat_{j}_{level}' for j in range(16) for level in ['upper','lower']])
bpy.ops.file.pack_all()
bpy.ops.wm.save_as_mainfile(filepath=str(APP/'assets/avatars/source/anime-performance.blend'))
bpy.ops.export_scene.vrm(filepath=str(APP/'assets/avatars/source-models/anime-performance-v1.vrm'))
for name,ratio in [('Performance outerwear',.42),('Hair',.50),('Performance footwear',.65),('Pleated underdress',.55)]:
    obj=bpy.data.objects[name];assert not obj.data.shape_keys,(name,'facial morphs must stay intact')
    bpy.context.view_layer.objects.active=obj
    # Bake remaining shell thickness before simplifying the delivered surface.
    for modifier in list(obj.modifiers):
        if modifier.type!='ARMATURE':bpy.ops.object.modifier_apply(modifier=modifier.name)
    modifier=obj.modifiers.new('Mobile silhouette reduction','DECIMATE');modifier.ratio=ratio
    bpy.ops.object.modifier_apply(modifier=modifier.name)
bpy.ops.wm.save_as_mainfile(filepath=str(APP/'assets/avatars/source/anime-mobile.blend'),compress=True)
bpy.ops.export_scene.vrm(filepath=str(APP/'assets/avatars/source-models/anime-performance-mobile-v1.vrm'))
print('ANIME_EXPORT_COMPLETE')
