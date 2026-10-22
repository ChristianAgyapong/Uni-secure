"""
MEIC-ViT: A Multi-Scale Enhanced Vision Transformer for Network Intrusion Detection
Reference: Yeqiu Xiao et al., Computer Networks 282 (2026) 112273.

Architecture Components:
1. Path A: Global Statistical Feature Branch (5 stats -> 525-d -> MLP -> 64-d)
2. Path B: Row-Level Visual Embedding (2D Conv 1xW -> BN -> GELU -> 128-d per row)
3. Path C: Sequential Content Feature Extractor (1D Convs -> BN -> GELU -> Pool -> Linear -> 128-d per row)
4. Vision Transformer Encoder: 6 layers, 8 heads, 256 hidden dim, GELU, Dropout 0.1
5. Multi-View Fusion: (Transformer 256-d + Global Stats 64-d) = 320-d final feature space
6. Classification Head: Per-row linear projection + Top-K Mean Pooling (K=3)
7. Attention Heatmap Extraction: Supports Fig. 11 interpretability analysis
8. Stratified Focal Loss (gamma=2.5, dynamic class balancing)
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F

class StatBranch(nn.Module):
    """
    Path A: Global Statistical Feature Branch.
    Computes 5 statistical metrics along the spatial dimension:
    Mean, Max, Standard Deviation, Max-Mean Difference, Peak Ratio (Max / (|Mean| + 1e-6)).
    Dimension: 5 metrics * 3 channels * 35 width = 525 features.
    MLP: Linear(525, 256) -> BatchNorm1d(256) -> GELU -> Dropout(0.1) -> Linear(256, 64).
    """
    def __init__(self, width=35, channels=3, out_dim=64):
        super().__init__()
        in_dim = 5 * channels * width
        self.mlp = nn.Sequential(
            nn.Linear(in_dim, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(256, out_dim)
        )

    def forward(self, x):
        # x shape: (B, C, H, W)
        mean = x.mean(dim=2)  # (B, C, W)
        mx = x.max(dim=2).values  # (B, C, W)
        std = x.std(dim=2, unbiased=False)  # (B, C, W)
        diff = mx - mean  # (B, C, W)
        peak_ratio = mx / (mean.abs() + 1e-6)  # (B, C, W)
        stats = torch.cat([mean, mx, std, diff, peak_ratio], dim=1)  # (B, 5*C, W)
        stats_flat = stats.flatten(1)  # (B, 5*C*W) = (B, 525)
        
        # Guard against single-sample batch in BatchNorm during eval mode
        if stats_flat.size(0) == 1 and self.training:
            # Handle edge-case in training if batch size is 1
            return self.mlp[4](F.gelu(self.mlp[0](stats_flat)))
        return self.mlp(stats_flat)


class RowVisualBranch(nn.Module):
    """
    Path B: Row-Level Visual Embedding.
    Applies 2D asymmetric convolution with kernel size (1, W) and stride (1, 1).
    Captures holistic spatial-visual pattern across each horizontal row of features.
    Output: (B, H, 128)
    """
    def __init__(self, window=35, channels=3, out_dim=128):
        super().__init__()
        self.conv = nn.Conv2d(channels, out_dim, kernel_size=(1, window), stride=(1, 1))
        self.bn = nn.BatchNorm2d(out_dim)

    def forward(self, x):
        # x: (B, C, H, W) -> conv: (B, out_dim, H, 1)
        out = self.conv(x)
        if out.size(0) > 1 or not self.training:
            out = self.bn(out)
        return F.gelu(out).squeeze(-1).permute(0, 2, 1)  # (B, H, out_dim)


class SequentialContentBranch(nn.Module):
    """
    Path C: Sequential Content Feature Extractor.
    Captures fine-grained, localized sequential dependencies within each row.
    Two consecutive 1D convolutions (kernel=3, padding=1) with 64 and 128 channels,
    followed by Adaptive Average Pooling (1x1) and linear projection to 128 dimensions.
    Output: (B, H, 128)
    """
    def __init__(self, window=35, channels=3, out_dim=128):
        super().__init__()
        self.conv1 = nn.Conv1d(channels, 64, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(64)
        self.conv2 = nn.Conv1d(64, 128, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(128)
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.proj = nn.Linear(128, out_dim)

    def forward(self, x):
        B, C, H, W = x.shape
        xr = x.permute(0, 2, 1, 3).reshape(B * H, C, W)
        
        c1 = self.conv1(xr)
        if c1.size(0) > 1 or not self.training:
            c1 = self.bn1(c1)
        c1 = F.gelu(c1)
        
        c2 = self.conv2(c1)
        if c2.size(0) > 1 or not self.training:
            c2 = self.bn2(c2)
        c2 = F.gelu(c2)
        
        z = self.pool(c2).squeeze(-1)  # (B*H, 128)
        out = self.proj(z).view(B, H, -1)  # (B, H, out_dim)
        return out


class TransformerBlock(nn.Module):
    """
    Pre-norm Vision Transformer Encoder Layer with Attention Weight Extraction.
    Allows capturing attention maps for Fig. 11 visual interpretability.
    """
    def __init__(self, d_model=256, n_heads=8, d_ff=1024, dropout=0.1):
        super().__init__()
        self.attn = nn.MultiheadAttention(d_model, n_heads, dropout=dropout, batch_first=True)
        self.norm1 = nn.LayerNorm(d_model)
        self.norm2 = nn.LayerNorm(d_model)
        self.ffn = nn.Sequential(
            nn.Linear(d_model, d_ff),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_ff, d_model),
            nn.Dropout(dropout)
        )

    def forward(self, x, need_weights=False):
        normed_x = self.norm1(x)
        attn_out, weights = self.attn(normed_x, normed_x, normed_x, need_weights=need_weights, average_attn_weights=True)
        x = x + attn_out
        x = x + self.ffn(self.norm2(x))
        return x, weights


class MEICViT(nn.Module):
    """
    Full MEIC-ViT Architecture.
    - Front-End: Three-Path Parallel Feature Extraction (Path A, B, C)
    - Enriched Token Sequence: Concat(Path B [128-d], Path C [128-d]) = 256-d per row
    - Multi-Head Transformer Encoder: 6 layers, 8 heads, 256 hidden dim
    - Fusion: Concat(Transformer Row Tokens [256-d], Global Stats [64-d]) = 320-d
    - Decision Head: Row-wise Linear Classifier + Top-K Mean Pooling (K=3)
    """
    def __init__(self, num_classes=15, window=35, hidden_dim=256, n_layers=6, n_heads=8, topk=3):
        super().__init__()
        self.num_classes = num_classes
        self.window = window
        self.hidden_dim = hidden_dim
        self.topk = topk

        # Front-End Pathways
        self.stat_branch = StatBranch(width=window, out_dim=64)
        self.row_branch = RowVisualBranch(window=window, out_dim=128)
        self.seq_branch = SequentialContentBranch(window=window, out_dim=128)

        # Token Projection & Positional Embedding
        self.token_proj = nn.Linear(256, hidden_dim)
        self.pos_embed = nn.Parameter(torch.randn(1, window, hidden_dim) * 0.02)
        self.token_norm = nn.LayerNorm(hidden_dim)

        # Transformer Encoder Stack
        self.layers = nn.ModuleList([
            TransformerBlock(d_model=hidden_dim, n_heads=n_heads, d_ff=hidden_dim * 4, dropout=0.1)
            for _ in range(n_layers)
        ])
        self.out_norm = nn.LayerNorm(hidden_dim)

        # Final Feature Space: hidden_dim (256) + global_stats (64) = 320-d
        self.classifier = nn.Linear(hidden_dim + 64, num_classes)

    def forward(self, x, return_attention=False):
        """
        Args:
            x: Tensor of shape (B, 3, 35, 35), float32 normalized [0, 1]
            return_attention: If True, also returns the averaged attention map across layers (B, 35, 35)
        Returns:
            logits: (B, num_classes)
            avg_attn (optional): (B, 35, 35)
        """
        # 1. Global statistical feature (Path A) -> (B, 64)
        f_stat = self.stat_branch(x)

        # 2. Row visual (Path B) + sequential content (Path C) -> (B, 35, 256)
        tokens = torch.cat([self.row_branch(x), self.seq_branch(x)], dim=-1)

        # 3. Add learnable positional encoding and normalize
        h = self.token_norm(self.token_proj(tokens) + self.pos_embed)

        # 4. Multi-Layer Transformer Encoder
        attns = []
        for layer in self.layers:
            h, w = layer(h, need_weights=return_attention)
            if return_attention:
                attns.append(w)

        enc = self.out_norm(h)  # (B, 35, hidden_dim)

        # 5. Expand Path A along row dimension and fuse -> (B, 35, 320)
        f_stat_expanded = f_stat.unsqueeze(1).expand(-1, enc.size(1), -1)
        comb = torch.cat([enc, f_stat_expanded], dim=-1)

        # 6. Predict row-level logits and perform Top-K Mean Pooling (K=3)
        row_logits = self.classifier(comb)  # (B, 35, num_classes)
        final_logits = torch.topk(row_logits, min(self.topk, row_logits.size(1)), dim=1).values.mean(dim=1)

        if return_attention:
            # Average attention matrix across layers: (B, 35, 35)
            avg_attn = torch.stack(attns, dim=0).mean(dim=0)
            return final_logits, avg_attn

        return final_logits


class StratifiedFocalLoss(nn.Module):
    """
    Equation 7 from Paper:
    L = - (1 / B) * sum_i sum_c alpha_c * y_{i,c} * (1 - p_{i,c})^gamma * log(p_{i,c})
    with gamma = 2.5 and dynamically balanced alpha_c.
    """
    def __init__(self, gamma=2.5, alpha=None, reduction="mean"):
        super().__init__()
        self.gamma = gamma
        self.alpha = alpha  # Tensor of shape (C,) or None
        self.reduction = reduction

    def forward(self, logits, targets):
        # logits: (B, C), targets: (B,) class indices
        probs = F.softmax(logits, dim=-1)
        targets_one_hot = F.one_hot(targets, num_classes=logits.size(-1)).float()

        p_t = (probs * targets_one_hot).sum(dim=-1)  # (B,)
        log_p_t = torch.log(p_t.clamp(min=1e-7))

        focal_weight = torch.pow(1.0 - p_t, self.gamma)

        if self.alpha is not None:
            alpha_t = self.alpha.to(logits.device)[targets]
            focal_weight = focal_weight * alpha_t

        loss = -focal_weight * log_p_t

        if self.reduction == "mean":
            return loss.mean()
        elif self.reduction == "sum":
            return loss.sum()
        return loss
