"""Audit editable delivery rigs; baked motion is verified separately per frame."""
import bpy,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]/'assets/avatars/source'
results=[]
for family,filename in [('robot','robot-study.blend'),('human','human-motion.blend'),('anime','anime-motion.blend')]:
    bpy.ops.wm.open_mainfile(filepath=str(ROOT/filename))
    rigs=[obj for obj in bpy.context.scene.objects if obj.type=='ARMATURE']
    assert len(rigs)==1,(family,'one source rig required')
    rig=rigs[0];bones=set(rig.data.bones.keys())
    actions={action.name for action in bpy.data.actions}
    assert {'cup-kick','entrance','settle','idle'}<=actions,(family,actions)
    meshes=[obj for obj in bpy.context.scene.objects if obj.type=='MESH' and any(mod.type=='ARMATURE' and mod.object==rig for mod in obj.modifiers)]
    weighted=blended=0;maximum_error=0
    for obj in meshes:
        groups={group.index for group in obj.vertex_groups if group.name in bones}
        for vertex in obj.data.vertices:
            weights=[group.weight for group in vertex.groups if group.group in groups and group.weight>1e-8]
            if not weights:continue # Authoring helpers and masked source regions.
            weighted+=1;blended+=int(sum(weight>.01 for weight in weights)>1)
            maximum_error=max(maximum_error,abs(sum(weights)-1))
    assert weighted>1000,(family,weighted)
    assert maximum_error<.011,(family,'unnormalized deformation weights',maximum_error)
    if family!='robot':assert blended>500,(family,'continuous skin weighting',blended)
    result={'family':family,'source':filename,'bones':len(bones),'weightedVertices':weighted,'blendedVertices':blended,'maximumWeightSumError':maximum_error,'actions':sorted(actions)}
    results.append(result);print('SOURCE_AUDIT',json.dumps(result))
(ROOT/'source-validation.json').write_text(json.dumps({'results':results},indent=2)+chr(10))
