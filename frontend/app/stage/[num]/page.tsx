import type { ComponentType } from "react";
import { getStage } from "@/lib/api";
import { STAGE_TITLES, type StageData } from "@/lib/types";
import { Card, CardSub, CardTitle } from "@/components/ui/card";
import { StageView } from "@/components/stage-view";
import { topLevelStrings } from "@/lib/stage-tables";
import { Stage1View } from "@/components/stages/stage1-view";
import { Stage2View } from "@/components/stages/stage2-view";
import { Stage3View } from "@/components/stages/stage3-view";
import { Stage4View } from "@/components/stages/stage4-view";
import { Stage5View } from "@/components/stages/stage5-view";
import { Stage6View } from "@/components/stages/stage6-view";
import { Stage7View } from "@/components/stages/stage7-view";
import { Stage8View } from "@/components/stages/stage8-view";
import { Stage9View } from "@/components/stages/stage9-view";

export const dynamic = "force-dynamic";

// Stages whose root payload isn't array-shaped, or that warrant a premium
// dedicated layout, get a bespoke component instead of the generic
// table-detecting StageView.
const BESPOKE_VIEWS: Record<number, ComponentType<{ data: StageData }>> = {
  1: Stage1View,
  2: Stage2View,
  3: Stage3View,
  4: Stage4View,
  5: Stage5View,
  6: Stage6View,
  7: Stage7View,
  8: Stage8View,
  9: Stage9View,
};

export default async function StagePage({ params }: { params: Promise<{ num: string }> }) {
  const { num } = await params;
  const stageNum = Number(num);
  const title = STAGE_TITLES[stageNum] ?? `Stage ${stageNum}`;

  let data;
  let loadError: string | null = null;
  try {
    data = await getStage(stageNum);
  } catch (err) {
    loadError = err instanceof Error ? err.message : String(err);
  }

  if (loadError || !data) {
    return (
      <div className="space-y-4">
        <h1 className="text-2xl font-bold text-white">
          Stage {stageNum}: {title}
        </h1>
        <Card glow="critical" className="border-red-500/20">
          <CardTitle>Failed to load stage data</CardTitle>
          <CardSub className="mt-2 font-mono text-red-500">{loadError}</CardSub>
        </Card>
      </div>
    );
  }

  const meta = topLevelStrings(data);

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight">
          Stage {stageNum}: {title}
        </h1>
        {Object.keys(meta).length > 0 && (
          <div className="flex gap-3 flex-wrap mt-2 text-xs font-mono text-slate-400">
            {Object.entries(meta).map(([k, v]) => (
              <span key={k}>
                {k}=<span className="text-slate-300">{v}</span>
              </span>
            ))}
          </div>
        )}
      </div>
      {(() => {
        const Bespoke = BESPOKE_VIEWS[stageNum];
        return Bespoke ? <Bespoke data={data} /> : <StageView data={data} stageNum={stageNum} />;
      })()}
    </div>
  );
}
