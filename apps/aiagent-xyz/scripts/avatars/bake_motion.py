"""Bake retargeted world-space controls onto editable Blender source actions.

Verify the Blender pose against every input joint/frame, then encode the same
baked motion as ordinary GLTF TRS channels while preserving VRM metadata.
Run after build_human.py, build_anime.py, and capture_motion.mjs.
"""
import bpy,addon_utils,json,math,struct
from pathlib import Path
from mathutils import Matrix

APP=Path(__file__).resolve().parents[2]
SOURCE=APP/'assets/avatars/source'
OUT=APP/'public/models/avatars'
MODELS=APP/'assets/avatars/source-models'
C=Matrix.Rotation(math.pi/2,4,'X')
CI=C.inverted()

def matrix(values):
    return Matrix([values[i:i+4] for i in range(0,16,4)]).transposed()

def encode_glb(source, destination, motion):
    data=source.read_bytes()
    json_length=struct.unpack_from('<I',data,12)[0]
    document=json.loads(data[20:20+json_length])
    binary_start=20+json_length+8
    binary=bytearray(data[binary_start:])
    nodes=document['nodes'];names={node.get('name'):i for i,node in enumerate(nodes)}
    parents={child:i for i,node in enumerate(nodes) for child in node.get('children',[])}
    rest={name:matrix(value) for name,value in motion['sourceRest'].items()}
    accessors=document.setdefault('accessors',[]);views=document.setdefault('bufferViews',[])

    def accessor(values,width,kind):
        while len(binary)%4:binary.append(0)
        offset=len(binary)
        flat=[n for row in values for n in row]
        binary.extend(struct.pack('<'+'f'*len(flat),*flat))
        view=len(views);views.append({'buffer':0,'byteOffset':offset,'byteLength':len(flat)*4})
        index=len(accessors)
        item={'bufferView':view,'componentType':5126,'count':len(values),'type':kind}
        if width==1:item.update(min=[min(flat)],max=[max(flat)])
        accessors.append(item)
        return index

    def raw_rest(index):
        node=nodes[index]
        if node.get('name') in rest:return rest[node['name']]
        if 'matrix' in node:local=matrix(node['matrix'])
        else:
            from mathutils import Quaternion,Vector
            q=node.get('rotation',[0,0,0,1]);rotation=Quaternion((q[3],q[0],q[1],q[2]))
            local=Matrix.LocRotScale(Vector(node.get('translation',[0,0,0])),rotation,Vector(node.get('scale',[1,1,1])))
        return raw_rest(parents[index])@local if index in parents else local

    animations=[]
    for clip in motion['clips']:
        samplers=[];channels=[]
        time_accessor=accessor([[i/motion['fps']] for i in range(len(clip['frames']))],1,'SCALAR')
        constant_time=accessor([[0],[clip['duration']]],1,'SCALAR')
        transforms=[{name:matrix(value) for name,value in frame.items()} for frame in clip['frames']]
        for name,index in names.items():
            if name not in rest:continue
            parent_index=parents.get(index);parent_name=nodes[parent_index].get('name') if parent_index is not None else None
            values={'translation':[],'rotation':[],'scale':[]};previous=None
            for frame in transforms:
                parent=frame.get(parent_name) if parent_name in frame else raw_rest(parent_index) if parent_index is not None else Matrix.Identity(4)
                local=parent.inverted_safe()@frame[name]
                position,rotation,scale=local.decompose()
                if previous is not None and previous.dot(rotation)<0:rotation.negate()
                previous=rotation.copy()
                values['translation'].append(list(position));values['rotation'].append([rotation.x,rotation.y,rotation.z,rotation.w]);values['scale'].append(list(scale))
            for path,rows in values.items():
                constant=max(abs(value-rows[0][i]) for row in rows for i,value in enumerate(row))<1e-6
                if constant:rows=[rows[0],rows[0]]
                output=accessor(rows,4 if path=='rotation' else 3,'VEC4' if path=='rotation' else 'VEC3')
                sampler=len(samplers);samplers.append({'input':constant_time if constant else time_accessor,'output':output,'interpolation':'LINEAR'})
                channels.append({'sampler':sampler,'target':{'node':index,'path':path}})
        animations.append({'name':clip['name'],'samplers':samplers,'channels':channels,'extras':{'source':'Blender verified humanoid-v1 controls','fps':motion['fps']}})
    document['animations']=animations
    document['buffers']=[{'byteLength':len(binary)}]
    document.setdefault('asset',{}).setdefault('extras',{})['avatarMotionRevision']='performance-v1'
    js=json.dumps(document,separators=(',',':')).encode()
    js+=b' '*((-len(js))%4);binary.extend(b'\0'*((-len(binary))%4))
    destination.write_bytes(struct.pack('<4sII',b'glTF',2,12+8+len(js)+8+len(binary))+struct.pack('<II',len(js),0x4e4f534a)+js+struct.pack('<II',len(binary),0x004e4942)+binary)

reports=[]
for family,blend_name,asset_name,result_name in [
    ('human','human-authored.blend','human-authored-v1.glb','human-performance-v1.glb'),
    ('anime','anime-performance.blend','anime-performance-v1.vrm','anime-performance-baked-v1.vrm'),
]:
    bpy.ops.wm.open_mainfile(filepath=str(SOURCE/blend_name))
    bpy.context.preferences.filepaths.save_version=0
    rig=next(obj for obj in bpy.data.objects if obj.type=='ARMATURE')
    motion=json.loads((APP/'assets/avatars/motion'/f'{family}-controls.json').read_text())
    rig.animation_data_clear();rig.animation_data_create()
    for pb in rig.pose.bones:
        for constraint in list(pb.constraints):pb.constraints.remove(constraint)
        pb.rotation_mode='QUATERNION'
    rest={name:matrix(value) for name,value in motion['sourceRest'].items()}
    ordered=[bone for bone in rig.data.bones if bone.name in rest]
    ordered.sort(key=lambda bone:len(bone.parent_recursive))
    maximum=0
    for clip in motion['clips']:
        action=bpy.data.actions.new(clip['name']);action.use_fake_user=True
        rig.animation_data.action=action
        for frame,values in enumerate(clip['frames']):
            bpy.context.scene.frame_set(frame)
            desired={bone.name:C@matrix(values[bone.name])@rest[bone.name].inverted_safe()@CI@bone.matrix_local for bone in ordered}
            for bone in ordered:
                parent=bone.parent
                basis=bone.matrix_local.inverted_safe()
                if parent:basis=basis@parent.matrix_local@desired.get(parent.name,parent.matrix_local).inverted_safe()
                basis=basis@desired[bone.name]
                pb=rig.pose.bones[bone.name];pb.matrix_basis=basis
                pb.keyframe_insert('location',frame=frame,group=bone.name)
                pb.keyframe_insert('rotation_quaternion',frame=frame,group=bone.name)
                pb.keyframe_insert('scale',frame=frame,group=bone.name)
            bpy.context.view_layer.update()
            for bone in ordered:
                actual=rig.pose.bones[bone.name].matrix
                maximum=max(maximum,max(abs(actual[i][j]-desired[bone.name][i][j]) for i in range(4) for j in range(4)))
        # Stash an ordinary clip action for Blender's action editor.
        track=rig.animation_data.nla_tracks.new();track.name=clip['name']
        strip=track.strips.new(clip['name'],0,action);strip.action_frame_start=0;strip.action_frame_end=clip['duration']*motion['fps']
        track.mute=True
    rig.animation_data.action=next(action for action in bpy.data.actions if action.name=='cup-kick')
    bpy.context.scene.render.fps=motion['fps'];bpy.context.scene.frame_start=0;bpy.context.scene.frame_end=120
    bpy.context.scene.frame_set(0)
    assert maximum<.0001,(family,'Blender pose transfer mismatch',maximum)
    bpy.ops.wm.save_as_mainfile(filepath=str(SOURCE/f'{family}-motion.blend'),compress=True)
    encode_glb(MODELS/asset_name,OUT/result_name,motion)
    mobile_name=asset_name.replace('-v1.', '-mobile-v1.')
    if (MODELS/mobile_name).exists():
        encode_glb(MODELS/mobile_name,OUT/result_name.replace('-v1.','-mobile-v1.'),motion)
    reports.append({'body':family,'sourceJoints':len(ordered),'maximumMatrixError':maximum,'clips':[{'name':c['name'],'frames':len(c['frames'])} for c in motion['clips']]})
    print('BAKED',family,maximum)
(SOURCE/'bake-validation.json').write_text(json.dumps(reports,indent=2)+'\n')
