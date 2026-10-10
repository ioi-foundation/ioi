"""Reproducible Blender authoring and export for the articulated robot.

Run with Blender 4.5 LTS --background --python this_file -- [--family robot] [--quality desktop|mobile].
The shipped cyborg is the placement reference; the original separated .blend has
several displaced internal parts. Original assets are never overwritten.
"""
import argparse
import json
import math
import struct
import sys
import tempfile
from pathlib import Path

import bpy
from mathutils import Matrix, Quaternion, Vector

APP = Path(__file__).resolve().parents[2]
OUT = APP / "public/models/avatars"
SOURCE = APP / "assets/avatars/source"
FPS = 30
TAU = math.tau
CHOREOGRAPHY = json.loads((APP / 'shared/avatar-choreography.json').read_text())


def vec(x):
    return Vector(x)


def material(name, color, metallic=0, roughness=.65):
    m = bpy.data.materials.new(name)
    m.diffuse_color = (*color, 1)
    m.use_nodes = True
    bsdf = m.node_tree.nodes.get("Principled BSDF")
    bsdf.inputs["Base Color"].default_value = (*color, 1)
    bsdf.inputs["Metallic"].default_value = metallic
    bsdf.inputs["Roughness"].default_value = roughness
    return m


def mesh_object(name, vertices, faces, mat, group=None):
    data = bpy.data.meshes.new(name)
    data.from_pydata(vertices, [], faces)
    data.update()
    obj = bpy.data.objects.new(name, data)
    bpy.context.collection.objects.link(obj)
    obj.data.materials.append(mat)
    for polygon in data.polygons:
        polygon.use_smooth = True
    if group:
        obj.vertex_groups.new(name=group).add(list(range(len(vertices))), 1, "REPLACE")
    return obj


def apply_transform(obj):
    bpy.ops.object.select_all(action="DESELECT")
    obj.select_set(True)
    bpy.context.view_layer.objects.active = obj
    bpy.ops.object.transform_apply(location=True, rotation=True, scale=True)


def ellipsoid(name, center, scale, mat, group, segments=20, rings=12):
    bpy.ops.mesh.primitive_uv_sphere_add(segments=segments, ring_count=rings, location=center)
    obj = bpy.context.object
    obj.name = name
    obj.scale = scale
    apply_transform(obj)
    obj.data.materials.append(mat)
    for p in obj.data.polygons:
        p.use_smooth = True
    obj.vertex_groups.new(name=group).add(list(range(len(obj.data.vertices))), 1, "REPLACE")
    return obj


def rings_mesh(name, rings, mat, group, segments=24):
    vertices, faces = [], []
    for cx, cy, z, rx, ry in rings:
        for j in range(segments):
            a = TAU * j / segments
            vertices.append((cx + rx * math.cos(a), cy + ry * math.sin(a), z))
    for k in range(len(rings) - 1):
        for j in range(segments):
            a = k * segments + j
            b = k * segments + (j + 1) % segments
            faces.append((a, b, b + segments, a + segments))
    faces.extend([tuple(reversed(range(segments))), tuple(range((len(rings)-1)*segments, len(rings)*segments))])
    return mesh_object(name, vertices, faces, mat, group)


def limb(name, a, b, radii, mat, group):
    a, b = vec(a), vec(b)
    direction = (b-a).normalized()
    right = direction.cross(vec((0, 1, 0))).normalized()
    back = direction.cross(right).normalized()
    vertices, faces = [], []
    count = 16
    for k, (t, radius) in enumerate(radii):
        center = a.lerp(b, t)
        for j in range(count):
            phase = TAU*j/count
            vertices.append(center + right*math.cos(phase)*radius + back*math.sin(phase)*radius*.9)
        if k:
            for j in range(count):
                lo = (k-1)*count
                hi = k*count
                faces.append((lo+j, lo+(j+1)%count, hi+(j+1)%count, hi+j))
    faces.extend([tuple(reversed(range(count))), tuple(range((len(radii)-1)*count, len(radii)*count))])
    return mesh_object(name, vertices, faces, mat, group)


def shoe_loft(name, outline, levels, side, mat):
    """A shaped shoe last with planar caps and independently shaded bevels."""
    sign = 1 if side == 'left' else -1
    center = vec((sum(p[0] for p in outline)/len(outline), sum(p[1] for p in outline)/len(outline)))
    vertices, faces = [], []
    for z, scale in levels:
        for x, y in outline:
            p = center + (vec((x, y))-center)*scale
            vertices.append((sign*(.115+p.x), p.y, z))
    n = len(outline)
    for k in range(len(levels)-1):
        for j in range(n):
            faces.append((k*n+j, k*n+(j+1)%n, (k+1)*n+(j+1)%n, (k+1)*n+j))
    faces += [tuple(reversed(range(n))), tuple(range((len(levels)-1)*n, len(levels)*n))]
    if sign < 0: faces = [tuple(reversed(face)) for face in faces]
    obj = mesh_object(name, vertices, faces, mat, side+'Foot')
    # Flat soles must stay flat under lighting. Smoothing across the cap is
    # what made the earlier outsole look like an inflated black egg.
    for polygon in obj.data.polygons: polygon.use_smooth = False
    return obj


def robot_foot(side, mats):
    outline = [(0,-.177),(.031,-.174),(.049,-.157),(.057,-.132),(.057,-.106),
               (.048,-.068),(.039,-.025),(.039,.018),(.041,.058),(.035,.081),
               (.023,.093),(0,.097),(-.024,.093),(-.036,.079),(-.039,.056),
               (-.032,.021),(-.028,-.014),(-.033,-.047),(-.047,-.084),
               (-.053,-.115),(-.049,-.145),(-.033,-.167)]
    # Subdivide only the perimeter, preserving the narrow medial arch and heel.
    rounded = []
    for j in range(len(outline)):
        a, b, c, d = [vec(outline[k % len(outline)]) for k in [j-1,j,j+1,j+2]]
        for step in range(3):
            t=step/3
            rounded.append(tuple(.5*((2*b)+(-a+c)*t+(2*a-5*b+4*c-d)*t*t+(-a+3*b-3*c+d)*t*t*t)))
    meshes = [shoe_loft(side+' shaped outsole',rounded,[(.012,.96),(.020,1),(.035,1),(.043,.94)],side,mats['sole'])]
    # Armor sits above a thin contrasting welt, rather than swelling the sole.
    meshes.append(shoe_loft(side+' perimeter welt',rounded,[(.040,.94),(.046,.96),(.049,.90)],side,mats['shell']))
    toe = [(-.043,-.151),(-.029,-.168),(0,-.175),(.030,-.169),(.047,-.151),(.051,-.129),(.049,-.112),(-.046,-.112),(-.049,-.132)]
    meshes.append(shoe_loft(side+' toe armor',toe,[(.047,1),(.060,.97),(.079,.83),(.085,.65)],side,mats['shell']))
    forefoot = [(-.045,-.105),(.049,-.105),(.044,-.077),(.037,-.046),(-.032,-.046),(-.039,-.074)]
    meshes.append(shoe_loft(side+' metatarsal armor',forefoot,[(.047,1),(.076,.97),(.091,.69)],side,mats['shell']))
    sign=1 if side=='left' else -1
    meshes.append(rings_mesh(side+' ankle saddle',[
        (sign*.115,.025,.043,.033,.066),
        (sign*.115,.026,.072,.035,.063),
        (sign*.115,.037,.111,.033,.043),
        (sign*.115,.045,.155,.027,.029),
    ],mats['shell'],side+'Foot',32))
    # Raised split chevrons, a recessed arch bridge and a discrete heel block
    # remain legible in the sole-facing kick, without bitmap detail.
    for row,(y,width) in enumerate([(-.154,.030),(-.135,.042),(-.115,.044),(-.095,.038),(-.076,.033)]):
        for half in [-1,1]:
            pad=[(half*.006,y+.003),(half*width,y-.007),(half*width,y+.003),(half*.006,y+.013)]
            if half<0: pad.reverse()
            meshes.append(shoe_loft(f'{side} tread {row} {half}',pad,[(.003,.85),(.006,1),(.013,1)],side,mats['tread']))
    heel=[(-.024,.040),(.026,.040),(.031,.067),(.021,.084),(-.019,.085),(-.029,.070)]
    meshes.append(shoe_loft(side+' heel pad',heel,[(.003,.85),(.006,1),(.013,1)],side,mats['tread']))
    bridge=[(-.007,-.044),(.007,-.044),(.007,.027),(-.007,.027)]
    meshes.append(shoe_loft(side+' arch bridge',bridge,[(.009,.90),(.015,1)],side,mats['mechanism']))
    return meshes




def smoothstep(value):
    value=max(0,min(1,value))
    return value*value*(3-2*value)






def rig_spec():
    data = {
        "root": ((0, 0, 0), (0, 0, .15), None),
        "hips": ((0, 0, 1.02), (0, 0, 1.15), "root"),
        "spine": ((0, 0, 1.15), (0, 0, 1.34), "hips"),
        "chest": ((0, 0, 1.34), (0, 0, 1.48), "spine"),
        "neck": ((0, 0, 1.48), (0, 0, 1.58), "chest"),
        "head": ((0, 0, 1.58), (0, 0, 1.8), "neck"),
    }
    for side, s in [("left", 1), ("right", -1)]:
        data.update({
            side+"Shoulder": ((s*.045, .07, 1.46), (s*.155, .085, 1.465), "chest"),
            side+"UpperArm": ((s*.155, .085, 1.465), (s*.335, .100, 1.285), side+"Shoulder"),
            side+"LowerArm": ((s*.335, .100, 1.285), (s*.487, .032, 1.1446), side+"UpperArm"),
            side+"Hand": ((s*.487, .032, 1.1446), (s*.535, .02, 1.07), side+"LowerArm"),
            side+"UpperLeg": ((s*.1, .015, 1.0), (s*.109, 0, .615), "hips"),
            side+"LowerLeg": ((s*.109, 0, .615), (s*.115, .045, .155), side+"UpperLeg"),
            side+"Foot": ((s*.115, .045, .155), (s*.115, -.07, .045), side+"LowerLeg"),
            side+"Toes": ((s*.115, -.07, .045), (s*.115, -.13, .045), side+"Foot"),
        })
        for finger, offset, length in [("Thumb", -.027,.67), ("Index", -.015,.85), ("Middle", 0,1), ("Ring", .014,.90), ("Little", .026,.72)]:
            for joint in range(3):
                base = (s*(.528 + joint*.015*length), .02+offset, 1.082-joint*.021*length)
                tip = (s*(.528 + (joint+1)*.015*length), .02+offset, 1.082-(joint+1)*.021*length)
                data[f"{side}{finger}{joint+1}"] = (base, tip, side+"Hand" if joint == 0 else f"{side}{finger}{joint}")
        data[side+"Coat"] = ((s*.11, .01, 1.03), (s*.19, .025, .62), "hips")
    data["rightGrip"] = ((-.52, -.025, 1.11), (-.52, -.025, 1.18), "rightHand")
    data["hair"] = ((0, .04, 1.7), (0, .05, 1.36), "head")
    return data


def create_rig(spec):
    data = bpy.data.armatures.new("HumanoidV1")
    rig = bpy.data.objects.new("AvatarRig", data)
    bpy.context.collection.objects.link(rig)
    bpy.context.view_layer.objects.active = rig
    rig.select_set(True)
    bpy.ops.object.mode_set(mode="EDIT")
    for name, (head, tail, parent) in spec.items():
        b = data.edit_bones.new(name)
        b.head, b.tail = head, tail
        b.roll = 0
        if parent:
            b.parent = data.edit_bones[parent]
    bpy.ops.object.mode_set(mode="OBJECT")
    rig["rigVersion"] = "humanoid-v1"
    rig["family"] = "motion-study"
    return rig


def classify_robot(name, center):
    n = name.lower()
    x, _, z = center
    side = "left" if x > 0 else "right"
    if "head" in n or "skull" in n:
        return "head"
    if "arm_" in n:
        side = "left" if "arm_left" in n else "right"
        if "hand" in n or "finger" in n or "thumb" in n or abs(x)>.49 or z<1.12:
            return side+"Hand"
        if "forearm" in n or "elbow" in n or abs(x)>.33 or z<1.28:
            return side+"LowerArm"
        return side+"UpperArm"
    if "leg_" in n or "left_right" in n:
        if "foot" in n or z<.20:
            return side+"Foot"
        if "shin" in n or "calf" in n or "knee" in n or z<.64:
            return side+"LowerLeg"
        return side+"UpperLeg"
    if "neck" in n and z>1.49:
        return "neck"
    if "chest" in n or "scapula" in n or z>1.34:
        return "chest"
    if "pelvis" in n or "buttox" in n or z<1.14:
        return "hips"
    return "spine"


def robot_meshes(mats,spec,quality):
    # Keep the authored outside normals intact when selecting shell surfaces.
    # Editing imported custom-normal loop data with bmesh/decimate directly
    # corrupts its shading; filter primitives before import, then transfer the
    # original outside normals to the simplified delivery surface.
    source=(APP / "public/models/cyborg/cyborg_female_separated.glb").read_bytes()
    size=struct.unpack_from('<I',source,12)[0]
    document=json.loads(source[20:20+size])
    for model in document['meshes']:
        outside=[p for p in model['primitives'] if 'inside' not in document['materials'][p['material']]['name']]
        if outside:model['primitives']=outside
    encoded=json.dumps(document,separators=(',',':')).encode()
    encoded+=b' '*((-len(encoded))%4)
    tail=source[20+size:]
    filtered=struct.pack('<4sII',b'glTF',2,20+len(encoded)+len(tail))+struct.pack('<II',len(encoded),0x4e4f534a)+encoded+tail
    with tempfile.TemporaryDirectory(prefix='aiagent-robot-') as staging:
        asset=Path(staging)/'outside.glb';asset.write_bytes(filtered)
        bpy.ops.import_scene.gltf(filepath=str(asset))
    originals = [o for o in bpy.context.scene.objects if o.type == "MESH"]
    meshes=[]
    mapping = []
    for obj in originals:
        apply_transform(obj)
        center = sum((vec(c) for c in obj.bound_box), Vector())/8
        bone = classify_robot(obj.name, center)
        record={"part": obj.name, "bone": bone, "center": list(center)}
        mapping.append(record)
        if bone.endswith("Hand") or bone.endswith("Foot"):
            record["replacement"]="articulated palm and finger segments" if bone.endswith("Hand") else "forward-facing articulated foot with outsole"
            bpy.data.objects.remove(obj,do_unlink=True)
            continue
        if 'skeleton' in obj.name and (bone.endswith(('UpperArm','LowerArm')) or bone=='neck'):
            record['replacement']='joint-aligned mechanical core'
            bpy.data.objects.remove(obj,do_unlink=True)
            continue
        meshes.append(obj)
        if len(obj.data.polygons) > 180 and (quality=='mobile' or 'skeleton' in obj.name):
            normal_source=None
            if 'skeleton' not in obj.name:
                normal_source=obj.copy();normal_source.data=obj.data.copy()
                bpy.context.collection.objects.link(normal_source)
            mod = obj.modifiers.new("Delivery simplification", "DECIMATE")
            mod.ratio = (.12 if quality=='mobile' else .40) if "skeleton" in obj.name else .70 if 'head' in obj.name.lower() else .35
            bpy.context.view_layer.objects.active = obj
            bpy.ops.object.modifier_apply(modifier=mod.name)
            if normal_source:
                normals=obj.modifiers.new('Authored surface normals','DATA_TRANSFER')
                normals.object=normal_source;normals.use_loop_data=True
                normals.data_types_loops={'CUSTOM_NORMAL'};normals.loop_mapping='POLYINTERP_NEAREST'
                bpy.ops.object.modifier_apply(modifier=normals.name)
                mesh=normal_source.data;bpy.data.objects.remove(normal_source,do_unlink=True);bpy.data.meshes.remove(mesh)
        if obj.data.has_custom_normals and 'skeleton' in obj.name:
            obj.data.normals_split_custom_set([(0,0,0)]*len(obj.data.loops))
        obj.data.materials.clear()
        obj.data.materials.append(mats["mechanism"] if "skeleton" in obj.name else mats["shell"])
        obj.vertex_groups.clear()
        obj.vertex_groups.new(name=bone).add(list(range(len(obj.data.vertices))), 1, "REPLACE")
        for p in obj.data.polygons:
            p.material_index = 0
            p.use_smooth = True
    (SOURCE / "robot-part-map.json").write_text(json.dumps(mapping, indent=2)+"\n")
    for sign in [-1,1]:
        meshes.append(ellipsoid("Optic housing",(sign*.028,-.061,1.680),(.018,.008,.006),mats["mechanism"],"head",24,12))
        meshes.append(ellipsoid("Optic light",(sign*.028,-.068,1.680),(.012,.003,.0032),mats["eyes"],"head",24,12))
        meshes.append(ellipsoid('Headset receiver',(sign*.091,.053,1.688),(.015,.025,.035),mats['headset'],'head',24,12))
    for i in range(24):
        a=i*math.pi/24;b=(i+1)*math.pi/24
        points=[(.100*math.cos(angle),.055,1.690+.132*math.sin(angle)) for angle in [a,b]]
        meshes.append(limb('Headset band',*points,[(0,.007),(1,.007)],mats['headset'],'head'))
    meshes.append(ellipsoid('Neck core',(0,.067,1.554),(.039,.034,.060),mats['mechanism'],'neck',24,16))
    for side in ["left","right"]:
        for segment in ['UpperArm','LowerArm']:
            a,b,_=spec[side+segment]
            meshes.append(limb(side+segment+' core',a,b,[(0,.020),(.5,.021),(1,.018)],mats['mechanism'],side+segment))
        for joint,radius in [("UpperArm",.032),("LowerArm",.031),("Hand",.022),
            ("UpperLeg",.049),("LowerLeg",.037),("Foot",.025)]:
            meshes.append(ellipsoid(side+joint+" seal",spec[side+joint][0],(radius,radius,radius),mats["mechanism"],side+joint))
        a,b,_=spec[side+"Hand"]
        meshes.append(limb(side+"Palm",a,b,[(0,.022),(.45,.029),(1,.022)],mats["shell"],side+"Hand"))
        for finger in ["Thumb","Index","Middle","Ring","Little"]:
            for j in range(1,4):
                name=f"{side}{finger}{j}"
                a,b,_=spec[name]
                meshes.append(limb(name,a,b,[(0,.0058),(.7,.005),(1,.0045)],mats["shell"],name))
                meshes.append(ellipsoid(name+" knuckle",a,(.006,.006,.006),mats["mechanism"],name,12,8))
        meshes.extend(robot_foot(side,mats))
    return meshes




def cup_meshes(mats, spec):
    center = vec(spec["rightGrip"][0])
    rings = [(center.x,center.y,center.z+z,r,r) for z,r in [(0,.025),(.008,.027),(.054,.043),(.059,.044),(.059,.039),(.012,.023)]]
    cup = rings_mesh("Cup",rings,mats["porcelain"],"rightGrip",32)
    bpy.ops.mesh.primitive_torus_add(major_segments=24,minor_segments=8,location=center+vec((-.050,0,.032)),rotation=(math.pi/2,0,0),major_radius=.022,minor_radius=.005)
    handle=bpy.context.object
    handle.name="Cup handle"
    apply_transform(handle)
    handle.data.materials.append(mats["porcelain"])
    handle.vertex_groups.new(name="rightGrip").add(list(range(len(handle.data.vertices))),1,"REPLACE")
    return [cup,handle]


def join_meshes(meshes, rig):
    bpy.ops.object.select_all(action="DESELECT")
    for m in meshes:
        m.select_set(True)
    bpy.context.view_layer.objects.active=meshes[0]
    bpy.ops.object.join()
    obj=bpy.context.object
    obj.name="AvatarSurface"
    mod=obj.modifiers.new("Humanoid skin","ARMATURE")
    mod.object=rig
    obj.parent=rig
    return obj


def solve_chain(a, target, pole, length_a, length_b):
    delta=target-a
    distance=min(delta.length,length_a+length_b-.0001)
    distance=max(distance,abs(length_a-length_b)+.0001)
    direction=delta.normalized()
    end=a+direction*distance
    along=(length_a**2-length_b**2+distance**2)/(2*distance)
    bend=pole-a
    bend=(bend-direction*bend.dot(direction)).normalized()
    joint=a+direction*along+bend*math.sqrt(max(0,length_a**2-along**2))
    return joint,end


def pose_segment(rig,name,head,tail,matrices,rotation=None):
    rest=rig.data.bones[name]
    q=rotation or (rest.tail_local-rest.head_local).normalized().rotation_difference((tail-head).normalized())
    desired=Matrix.Translation(head)@q.to_matrix().to_4x4()@rest.matrix_local.to_3x3().to_4x4()
    # Convert against this frame's parent target, never Blender's dependency-
    # graph pose from the preceding frame. That stale parent creates joint gaps.
    basis=rest.matrix_local.inverted()@desired
    if rest.parent:
        basis=rest.matrix_local.inverted()@rest.parent.matrix_local@matrices[rest.parent.name].inverted()@desired
    bone=rig.pose.bones[name]
    bone.rotation_mode="QUATERNION"
    bone.location,bone.rotation_quaternion,bone.scale=basis.decompose()
    matrices[name]=desired


def pose_fingers(rig,spec,side,matrices,openness=0):
    hand=side+"Hand"
    transform=matrices[hand]@rig.data.bones[hand].matrix_local.inverted()
    spread=(transform.to_3x3()@vec((0,1 if side=="left" else -1,0))).normalized()
    for finger in ["Thumb","Index","Middle","Ring","Little"]:
        head=transform@vec(spec[f"{side}{finger}1"][0])
        for j,angle in enumerate([.95,2.15,3.00],1):
            name=f"{side}{finger}{j}"
            a,b,_=spec[name]
            direction=transform.to_3x3()@(vec(b)-vec(a))
            # Opposing thumb and curled phalanges form a handle grip / free fist.
            direction=Quaternion(spread,angle*(.7 if finger=="Thumb" else 1)*(1-.85*openness))@direction
            tail=head+direction
            pose_segment(rig,name,head,tail,matrices)
            head=tail


def motion_pose(rig,spec,time,mode):
    matrices={}
    def segment(name,head,tail):
        pose_segment(rig,name,head,tail,matrices)
    # The support foot slides backward on the floor. Its next lifted step
    # recovers that travel, giving a periodic shuffle without root drift.
    period=4
    resting=mode in ["idle","settle"]
    relaxation=1 if mode=="idle" else smoothstep(time/1.2) if mode=="settle" else 0
    phase=0 if resting else time/(2 if mode=="entrance" else period)
    sway=-math.sin(phase*TAU)*.045 if mode!="idle" else math.sin(phase*TAU)*.008
    bob=(1-math.cos(phase*TAU*2))*.012 if mode!="idle" else math.sin(phase*TAU)*.003
    # Keep reach reserve in the support leg. An upward pelvis bob on a fully
    # extended rest leg otherwise pulls a supposedly planted ankle off the floor.
    root=vec((sway,(1-math.cos(phase*TAU*2))*.025,bob-.050))
    if mode=="idle":root.z+=math.sin(time*TAU/4)*.003
    entrance=mode=="entrance"
    airborne=math.sin(math.pi*min(1,time/1.6))**2 if entrance and time<1.6 else 0
    if entrance:
        root.x += -0.8*(1-min(time/2,1))**2
        root.z += airborne*.30
    strut=math.sin(phase*TAU-CHOREOGRAPHY['strutLag'])*(1-relaxation)*(1-airborne)
    torso_yaw=strut*CHOREOGRAPHY['torsoTwist']
    hip_yaw=-strut*CHOREOGRAPHY['hipTwist']
    yaw_by_bone={'hips':hip_yaw,'spine':torso_yaw*.5,'chest':torso_yaw,
                 'neck':torso_yaw*.4,'head':torso_yaw*.2,
                 'leftShoulder':torso_yaw,'rightShoulder':torso_yaw}
    for name in ["root","hips","spine","chest","neck","head","leftShoulder","rightShoulder"]:
        a,b,_=spec[name]
        rotation=Quaternion(vec((0,0,1)),yaw_by_bone.get(name,0))
        a,b=rotation@vec(a)+root,rotation@vec(b)+root
        if name=="root":
            a,b=root,root+vec((0,0,.15))
        pose_segment(rig,name,a,b,matrices,rotation)
    for side,s in [("left",1),("right",-1)]:
        offset=0 if side=="left" else .5
        local=(phase+offset)%1
        score=CHOREOGRAPHY
        step=max(0,min(1,(local-score['swingStart'])/(score['swingEnd']-score['swingStart'])))
        beats=score['beats']
        support_phase=local+1 if local<=score['swingStart'] else local
        travel=smoothstep((support_phase-score['shuffleStart'])/(score['shuffleEnd']-score['shuffleStart']))
        forward=score['supportFront']+(score['supportBack']-score['supportFront'])*travel
        height,kick,outward=0,0,0
        if resting: forward=0
        if not resting and score['swingStart']<local<score['swingEnd']:
            for start,end in zip(beats,beats[1:]):
                if start[0]<=step<=end[0]:
                    t=(step-start[0])/(end[0]-start[0])
                    t=t*t*(3-2*t)
                    forward,height,kick,outward=[start[j]+(end[j]-start[j])*t for j in [1,2,3,4]]
                    break
        a=Quaternion(vec((0,0,1)),hip_yaw)@vec(spec[side+"UpperLeg"][0])+root
        knee_rest=vec(spec[side+"LowerLeg"][0])
        ankle_rest=vec(spec[side+"Foot"][0])
        foot=ankle_rest+vec((s*(score['stanceWidth']+outward),-forward,height))
        if entrance:
            wide=root+vec((s*(.76 if side=="left" else .62),-.14, .89 if side=="left" else .53))
            foot=foot.lerp(wide,airborne)
        knee,ankle=solve_chain(a,foot,a+vec((s*score['kneeOut'],-score['kneeForward'],.12)),(knee_rest-vec(spec[side+"UpperLeg"][0])).length,(ankle_rest-knee_rest).length)
        segment(side+"UpperLeg",a,knee)
        segment(side+"LowerLeg",knee,ankle)
        turn=Quaternion(vec((0,0,1)),s*score['turnout']*(1-kick*.7)*(1-airborne))
        rotation=turn@Quaternion(vec((1,0,0)),-math.radians(kick*90+airborne*35))
        foot_tip=ankle+rotation@(vec(spec[side+'Foot'][1])-ankle_rest)
        pose_segment(rig,side+'Foot',ankle,foot_tip,matrices,rotation)
        segment(side+'Toes',foot_tip,foot_tip+rotation@vec((0,-.06,0)))
        rig.pose.bones[side+'Foot'].scale*=vec((1+kick*.32,1+kick*.30,1+kick*.10))
        shoulder=Quaternion(vec((0,0,1)),torso_yaw)@vec(spec[side+"UpperArm"][0])+root
        if side=="right":
            hand=root+vec((-.135,-.14,1.589))
            hand+=vec((0,-.06,-.22))*relaxation
            hand=hand.lerp(root+vec((-.135,-.04,1.91)),airborne)
            pole=root+vec((-.6,-.13,1.3))
        else:
            raise_arm=max(0,math.sin(phase*TAU))**2 if mode!="idle" else 0
            hand=root+vec((.25,-.10,1.13+raise_arm*.64))
            hand+=vec((-.04,0,-.10))*relaxation
            hand=hand.lerp(root+vec((-.35,-.20,1.04)),airborne)
            pole=root+vec((.65,-.1,1.36))
        elbow,wrist=solve_chain(shoulder,hand,pole,(vec(spec[side+"LowerArm"][0])-vec(spec[side+"UpperArm"][0])).length,(vec(spec[side+"Hand"][0])-vec(spec[side+"LowerArm"][0])).length)
        segment(side+"UpperArm",shoulder,elbow)
        segment(side+"LowerArm",elbow,wrist)
        hand_tip=wrist+vec((.088,-.008,0)) if side=="right" else wrist+vec((0,-.055,.06)).lerp(vec((-.08,-.03,-.035)),airborne)
        segment(side+"Hand",wrist,hand_tip)
        pose_fingers(rig,spec,side,matrices,airborne if side=='left' else 0)
        if side=="right":
            grip=wrist+vec((.135,-.022,-.031))
            segment("rightGrip",grip,grip+vec((0,0,.07)))
    for side,s in [("left",1),("right",-1)]:
        a,b,_=spec[side+"Coat"]
        a,b=vec(a)+root,vec(b)+root
        local=(phase+(0 if side=="left" else .5))%1
        opening=math.sin(math.pi*(local-.1)/.38)**2 if .1<local<.48 and mode!="idle" else 0
        b+=vec((s*(.035+opening*.19),math.sin(phase*TAU+.6)*.035-opening*.08,opening*.15)) if mode!="idle" else vec((0,0,0))
        segment(side+"Coat",a,b)
    a,b,_=spec["hair"]
    segment("hair",vec(a)+root,vec(b)+root+vec((math.sin(phase*TAU+.5)*(.008 if mode=="idle" else .04),0,0)))


def bake_actions(rig,spec):
    rig.animation_data_create()
    for mode,duration in [("cup-kick",4),("entrance",2),("settle",1.2),("idle",4)]:
        action=bpy.data.actions.new(mode)
        rig.animation_data.action=action
        for frame in range(int(duration*FPS)+1):
            bpy.context.scene.frame_set(frame)
            motion_pose(rig,spec,frame/FPS,mode)
            for bone in rig.pose.bones:
                bone.rotation_mode="QUATERNION"
                bone.keyframe_insert(data_path="location",frame=frame,group=bone.name)
                bone.keyframe_insert(data_path="rotation_quaternion",frame=frame,group=bone.name)
                bone.keyframe_insert(data_path="scale",frame=frame,group=bone.name)
        action.use_fake_user=True
        track=rig.animation_data.nla_tracks.new()
        track.name=mode
        strip=track.strips.new(mode,0,action)
        strip.name=mode
        track.mute=True
    rig.animation_data.action=None
    for b in rig.pose.bones:
        b.matrix_basis=Matrix.Identity(4)


def build(family,quality='desktop'):
    bpy.ops.wm.read_factory_settings(use_empty=True)
    bpy.context.preferences.filepaths.save_version=0
    bpy.context.scene.render.fps=FPS
    mats={
        "shell":material("shell",(.62,.71,.74),.40,.48),
        "mechanism":material("mechanism",(.12,.20,.22),.6,.5),
        "sole":material("sole",(.14,.19,.21),.10,.76),
        "tread":material("tread",(.045,.063,.068),0,.88),
        "skin":material("skin",(.68,.40,.27) if family=="human" else (.92,.67,.52)),
        "jacket":material("jacket",(.11,.18,.23)),
        "coat":material("coat",(.85,.64,.43)),
        "trousers":material("trousers",(.095,.12,.16)),
        "boots":material("boots",(.08,.055,.048)),
        "hair":material("hair",(.12,.052,.042) if family=="anime" else (.08,.045,.026)),
        "white":material("white",(.96,.91,.80)),
        "iris":material("iris",(.03,.23,.25)),
        "lip":material("lip",(.44,.15,.11)),
        "accent":material("accent",(.67,.08,.038)),
        "porcelain":material("porcelain",(.97,.94,.84),0,.23),
        "eyes":material("eyes",(.04,.46,.42),.1,.28),
        "headset":material("headset",(.035,.075,.090),.55,.35),
    }
    optic=mats["eyes"].node_tree.nodes.get("Principled BSDF")
    optic.inputs["Emission Color"].default_value=(.03,.45,.39,1)
    optic.inputs["Emission Strength"].default_value=.7
    spec=rig_spec()
    meshes=robot_meshes(mats,spec,quality)
    meshes+=cup_meshes(mats,spec)
    bpy.ops.object.select_all(action="DESELECT")
    rig=create_rig(spec)
    surface=join_meshes(meshes,rig)
    rig["family"]=family
    rig["assetVersion"]="study-v1"
    surface["appearanceSlots"]="material-palette"
    bake_actions(rig,spec)
    bpy.context.scene.frame_set(0)
    stem=f"{family}-study"+('-mobile' if quality=='mobile' else '')
    bpy.ops.wm.save_as_mainfile(filepath=str(SOURCE/f"{stem}.blend"))
    bpy.ops.object.select_all(action="DESELECT")
    rig.select_set(True)
    surface.select_set(True)
    bpy.context.view_layer.objects.active=rig
    bpy.ops.export_scene.gltf(filepath=str(OUT/f"{stem}-v1.glb"),export_format="GLB",use_selection=True,
        export_animations=True,export_animation_mode="NLA_TRACKS",export_nla_strips=True,
        export_skins=True,export_extras=True,export_force_sampling=True,
        export_draco_mesh_compression_enable=True,export_draco_mesh_compression_level=6)
    triangles=sum(len(p.vertices)-2 for p in surface.data.polygons)
    report={"family":family,"rigVersion":"humanoid-v1","assetVersion":"study-v1","bones":list(spec),
        "triangles":triangles,"materials":len(surface.data.materials),"clips":["cup-kick","entrance","settle","idle"],
        "status":"authored robot with reconstructed joints and hands; qualification recorded with the avatar catalog"}
    report['quality']=quality
    (OUT/f"{stem}-v1.json").write_text(json.dumps(report,indent=2)+"\n")
    print("AVATAR_EXPORT",json.dumps(report))


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--family",choices=["robot"],default="robot")
    parser.add_argument("--quality",choices=['desktop','mobile'],default='desktop')
    args=parser.parse_args(sys.argv[sys.argv.index("--")+1:] if "--" in sys.argv else [])
    OUT.mkdir(parents=True,exist_ok=True)
    SOURCE.mkdir(parents=True,exist_ok=True)
    build(args.family,args.quality)
