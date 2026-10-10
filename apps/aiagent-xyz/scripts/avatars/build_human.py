"""Author the human family from fitted, CC0 MakeHuman meshes and textures.

Blender 4.5 LTS; MPFB 2.0.18 source and the CC0 system/suits01 packs.
This replaces the procedural engineering fixture, not the original cyborg.
"""
import importlib
import json
import math
import os
from pathlib import Path

import addon_utils
import bpy

APP=Path(__file__).resolve().parents[2]
TOOLS=Path(os.environ.get("AIAGENT_AUTHORING_TOOLS",Path.home()/".local/share/aiagent-tools"))
ASSETS=TOOLS/"mpfb-assets/data"
SOURCE=APP/"assets/avatars/source"
OUTPUT=APP/"assets/avatars/source-models"

bpy.ops.wm.read_factory_settings(use_empty=True)
bpy.context.preferences.filepaths.save_version=0
bpy.ops.preferences.extension_repo_add(name="Avatar authoring",type="LOCAL",use_custom_directory=True,
    custom_directory=str(TOOLS/"blender-extensions"))
package="bl_ext."+bpy.context.preferences.extensions.repos[-1].module+".mpfb"
addon_utils.enable(package,default_set=True)
mpfb=importlib.import_module(package)
mpfb.set_preference("mpfb_user_data",str(ASSETS.parent))
LocationService=importlib.import_module(package+".services.locationservice").LocationService
LocationService.__init__()
HumanService=importlib.import_module(package+".services.humanservice").HumanService
TargetService=importlib.import_module(package+".services.targetservice").TargetService
ExportService=importlib.import_module(package+".services.exportservice").ExportService
ObjectService=importlib.import_module(package+".services.objectservice").ObjectService
FaceService=importlib.import_module(package+".services.faceservice").FaceService

macro=TargetService.get_default_macro_info_dict()
macro.update(gender=1.0,age=.38,muscle=.45,weight=.43,height=.55,proportions=.55)
human=HumanService.create_human(macro_detail_dict=macro)
rig=HumanService.add_builtin_rig(human,"game_engine")
HumanService.set_character_skin(str(ASSETS/"skins/young_caucasian_male/young_caucasian_male.mhmat"),human,skin_type="GAMEENGINE")
chosen=[
    ("eyes/low-poly/low-poly.mhclo","Eyes"),
    ("eyebrows/eyebrow001/eyebrow001.mhclo","Eyebrows"),
    ("eyelashes/eyelashes01/eyelashes01.mhclo","Eyelashes"),
    ("teeth/teeth_base/teeth_base.mhclo","Teeth"),
    ("tongue/tongue01/tongue01.mhclo","Tongue"),
    ("hair/short02/short02.mhclo","Hair"),
    ("clothes/toigo_male_suit_tie_and_jacket/toigo_male_suit_tie_and_jacket.mhclo","Clothes"),
    ("clothes/shoes03/shoes03.mhclo","Clothes"),
]
for filename,kind in chosen:
    path=ASSETS/filename
    if not path.exists():
        raise FileNotFoundError(path)
    HumanService.add_mhclo_asset(str(path),human,asset_type=kind,material_type="GAMEENGINE",subdiv_levels=0)

for name in ['eyeBlinkLeft','eyeBlinkRight','mouthSmileLeft','mouthSmileRight','eyeLookInLeft','eyeLookOutRight']:
    TargetService.load_target(human,str(ASSETS/'targets/faceunits'/f'{name}.target'),name=name)
FaceService.interpolate_targets(human)

# Separate the already authored suit components by their topology. Its jacket
# hem gets its own controls; the trousers retain the fitted leg weighting.
suit=next(o for o in bpy.data.objects if o.type=='MESH' and 'toigo_male' in o.name)
adj=[set() for _ in suit.data.vertices]
for edge in suit.data.edges:
    a,b=edge.vertices;adj[a].add(b);adj[b].add(a)
components=[];seen=set()
for start in range(len(adj)):
    if start in seen:continue
    todo=[start];ids=[];seen.add(start)
    while todo:
        index=todo.pop();ids.append(index)
        for other in adj[index]-seen:seen.add(other);todo.append(other)
    components.append(ids)
jacket=max(components,key=len)
bpy.context.view_layer.objects.active=rig
bpy.ops.object.mode_set(mode='EDIT')
for j in range(8):
    angle=(j+.5)*math.tau/8
    bone=rig.data.edit_bones.new(f'coat_{j}_upper')
    bone.head=(math.sin(angle)*.12,-math.cos(angle)*.08,.99)
    bone.tail=(bone.head.x,bone.head.y,.73);bone.parent=rig.data.edit_bones['pelvis']
bpy.ops.object.mode_set(mode='OBJECT')
for index in jacket:
    p=suit.data.vertices[index].co
    if abs(p.x)>.25:continue
    influence=max(0,min(1,(1.015-p.z)/.11))
    if influence<=0:continue
    old=[(g.group,g.weight) for g in suit.data.vertices[index].groups]
    for group,weight in old:suit.vertex_groups[group].add([index],weight*(1-influence),'REPLACE')
    angle=math.atan2(p.x,-p.y)%math.tau
    a=(angle/math.tau*8-.5)%8;left=math.floor(a);fraction=a-left
    for j,w in [(left,1-fraction),((left+1)%8,fraction)]:
        group=suit.vertex_groups.get(f'coat_{j}_upper') or suit.vertex_groups.new(name=f'coat_{j}_upper')
        group.add([index],w*influence,'REPLACE')

tie=bpy.data.materials.new('tie');tie.use_nodes=True
p= tie.node_tree.nodes.get('Principled BSDF')
p.inputs['Base Color'].default_value=(.55,.025,.008,1);p.inputs['Roughness'].default_value=.45
suit.data.materials.append(tie)
tie_ids=set()
for ids in components:
    points=[suit.data.vertices[i].co for i in ids]
    if max(abs(p.x) for p in points)<.032 and min(p.z for p in points)>1.08:
        tie_ids.update(ids)
for polygon in suit.data.polygons:
    if all(i in tie_ids for i in polygon.vertices):polygon.material_index=len(suit.data.materials)-1

# Keep clothing color regions independent of skin, shirt and tie. The source
# texture remains available for the pinstripe option; solid palettes operate
# on the same fitted and weighted garment.
trousers=set()
for ids in components:
    points=[suit.data.vertices[i].co for i in ids]
    if min(p.z for p in points)<.15 and max(p.z for p in points)<1.15:trousers.update(ids)
for slot,ids in [('jacket',set(jacket)),('trousers',trousers)]:
    m=suit.data.materials[0].copy();m.name=slot
    suit.data.materials.append(m);index=len(suit.data.materials)-1
    for polygon in suit.data.polygons:
        if all(i in ids for i in polygon.vertices):polygon.material_index=index

# MPFB's game-engine graph wires every texture's alpha. Most textures are
# opaque; exporting them as BLEND sorts the eyes/teeth through the face and
# interleaves the suit's surfaces. Only hair cards/brows/lashes need cutouts.
for material in bpy.data.materials:
    if not material.use_nodes:
        continue
    cutout=any(token in material.name for token in ['eyebrow','eyelashes','short02'])
    for node in material.node_tree.nodes:
        if node.type=='BSDF_PRINCIPLED':
            alpha=node.inputs['Alpha']
            links=list(alpha.links)
            source=links[0].from_socket if links else None
            for link in links:
                material.node_tree.links.remove(link)
            alpha.default_value=1
            if cutout and source:
                threshold=material.node_tree.nodes.new('ShaderNodeMath')
                threshold.operation='GREATER_THAN'
                threshold.inputs[1].default_value=.4
                material.node_tree.links.new(source,threshold.inputs[0])
                material.node_tree.links.new(threshold.outputs[0],alpha)

mapping={"hips":"pelvis","spine":"spine_01","chest":"spine_02","upperChest":"spine_03","neck":"neck_01","head":"head"}
for side,suffix in [("left","l"),("right","r")]:
    for semantic,source in [("Shoulder","clavicle"),("UpperArm","upperarm"),("LowerArm","lowerarm"),("Hand","hand"),
        ("UpperLeg","thigh"),("LowerLeg","calf"),("Foot","foot"),("Toes","ball")]:
        mapping[side+semantic]=source+"_"+suffix
    for semantic,source in [("Thumb","thumb"),("Index","index"),("Middle","middle"),("Ring","ring"),("Little","pinky")]:
        segments=["Metacarpal","Proximal","Distal"] if semantic=="Thumb" else ["Proximal","Intermediate","Distal"]
        for index,segment in enumerate(segments,1):
            mapping[side+semantic+segment]=f"{source}_0{index}_{suffix}"
rig["rigVersion"]="humanoid-v1"
rig["humanoidBones"]=json.dumps(mapping)
rig["family"]="human"
rig["assetVersion"]="authored-v1"
# Blender normalizes armature weights while deforming; make that normalization
# explicit in the editable scene too, so other exporters see the same skin.
bone_names=set(rig.data.bones.keys())
for obj in bpy.context.scene.objects:
    if obj.type!='MESH' or not any(mod.type=='ARMATURE' and mod.object==rig for mod in obj.modifiers):continue
    deform_groups={group.index for group in obj.vertex_groups if group.name in bone_names}
    for vertex in obj.data.vertices:
        weights=[(group.group,group.weight) for group in vertex.groups if group.group in deform_groups]
        total=sum(weight for _,weight in weights)
        if total>1e-8:
            for index,weight in weights:obj.vertex_groups[index].add([vertex.index],weight/total,'REPLACE')
SOURCE.mkdir(parents=True,exist_ok=True)
OUTPUT.mkdir(parents=True,exist_ok=True)
bpy.ops.file.pack_all()
bpy.ops.wm.save_as_mainfile(filepath=str(SOURCE/"human-authored.blend"))

export_root=ExportService.create_character_copy(human,name_suffix="_delivery")
export_human=ObjectService.find_object_of_type_amongst_nearest_relatives(export_root,"Basemesh")
ExportService.bake_modifiers_remove_helpers(export_human,bake_masks=True,bake_subdiv=False,remove_helpers=True,also_proxy=True)
bpy.ops.object.select_all(action="DESELECT")
export_root.select_set(True)
children=ObjectService.get_list_of_children(export_root)
for obj in children:
    if obj.type=='MESH' and obj.data.shape_keys:
        keys=obj.data.shape_keys.key_blocks
        keep={k.name:[v.co-k.relative_key.data[i].co for i,v in enumerate(k.data)] for k in keys
              if k.name in ['eyeBlinkLeft','eyeBlinkRight','mouthSmileLeft','mouthSmileRight','eyeLookInLeft','eyeLookOutRight']}
        TargetService.bake_targets(obj)
        if keep:
            obj.shape_key_add(name='Basis')
            for name,deltas in keep.items():
                key=obj.shape_key_add(name=name)
                for i,delta in enumerate(deltas):key.data[i].co+=delta
    obj.select_set(True)
bpy.context.view_layer.objects.active=export_root
bpy.ops.export_scene.gltf(filepath=str(OUTPUT/"human-authored-v1.glb"),export_format="GLB",use_selection=True,
    export_skins=True,export_animations=False,export_extras=True,export_image_format="AUTO")
report={"family":"human","assetVersion":"authored-v1","source":"MakeHuman Community / Margaret Toigo CC0 assets",
    "macro":macro,"assets":[name for name,_ in chosen],"humanoidBones":mapping,
    "triangles":sum(len(p.vertices)-2 for o in children if o.type=="MESH" for p in o.data.polygons),
    "status":"Authored replacement; visual fit and retarget qualification pending"}
(OUTPUT/"human-authored-v1.json").write_text(json.dumps(report,indent=2)+"\n")
print("AUTHORED_HUMAN",json.dumps(report))

# Keep the expressive head unchanged on mobile; reduce hidden mouth geometry
# and the larger clothing surfaces where extra topology has little benefit.
for obj in children:
    if obj.type!='MESH' or obj.data.shape_keys:continue
    ratio=next((ratio for token,ratio in [('teeth_base',.12),('toigo_male',.60),('shoes03',.60),('short02',.65)] if token in obj.name),None)
    if ratio is None:continue
    bpy.context.view_layer.objects.active=obj
    modifier=obj.modifiers.new('Mobile silhouette reduction','DECIMATE');modifier.ratio=ratio
    bpy.ops.object.modifier_apply(modifier=modifier.name)
bpy.context.view_layer.objects.active=export_root
bpy.ops.export_scene.gltf(filepath=str(OUTPUT/'human-authored-mobile-v1.glb'),export_format='GLB',use_selection=True,
    export_skins=True,export_animations=False,export_extras=True,export_image_format='AUTO')
retained=set(children+[export_root])
for obj in list(bpy.context.scene.objects):
    if obj not in retained:bpy.data.objects.remove(obj,do_unlink=True)
bpy.ops.wm.save_as_mainfile(filepath=str(SOURCE/'human-mobile.blend'),compress=True)
