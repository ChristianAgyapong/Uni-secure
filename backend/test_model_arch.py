import torch
import torch.nn as nn
import torch.nn.functional as F

class StatBranch(nn.Module):
    def __init__(self, width=35, channels=3, out_dim=64):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(5 * channels * width, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(256, out_dim)
        )
    def forward(self, x):
        mean = x.mean(dim=2)
        mx = x.max(dim=2).values
        std = x.std(dim=2, unbiased=False)
        stats = torch.cat([mean, mx, std, mx - mean, mx / (mean.abs() + 1e-6)], dim=1)
        return self.mlp(stats.flatten(1))

class RowVisualBranch(nn.Module):
    def __init__(self, window=35, channels=3, out_dim=128):
        super().__init__()
        self.conv = nn.Conv2d(channels, out_dim, kernel_size=(1, window), stride=(1, 1))
        self.bn = nn.BatchNorm2d(out_dim)
    def forward(self, x):
        return F.gelu(self.bn(self.conv(x))).squeeze(-1).permute(0, 2, 1)

class SequentialContentBranch(nn.Module):
    def __init__(self, window=35, channels=3, out_dim=128):
        super().__init__()
        self.conv1 = nn.Sequential(nn.Conv1d(channels, 64, 3, padding=1), nn.BatchNorm1d(64), nn.GELU())
        self.conv2 = nn.Sequential(nn.Conv1d(64, 128, 3, padding=1), nn.BatchNorm1d(128), nn.GELU())
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.proj = nn.Linear(128, out_dim)
    def forward(self, x):
        B, C, H, W = x.shape
        xr = x.permute(0, 2, 1, 3).reshape(B * H, C, W)
        z = self.pool(self.conv2(self.conv1(xr))).squeeze(-1)
        return self.proj(z).view(B, H, -1)

class TransformerBlock(nn.Module):
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
    def __init__(self, num_classes=15, window=35, hidden_dim=256, n_layers=6, n_heads=8, topk=3):
        super().__init__()
        self.topk = topk
        self.window = window
        self.hidden_dim = hidden_dim
        self.stat_branch = StatBranch(width=window)
        self.row_branch = RowVisualBranch(window=window)
        self.seq_branch = SequentialContentBranch(window=window)
        
        self.token_proj = nn.Linear(256, hidden_dim)
        self.pos_embed = nn.Parameter(torch.randn(1, window, hidden_dim) * 0.02)
        self.token_norm = nn.LayerNorm(hidden_dim)
        
        self.layers = nn.ModuleList([
            TransformerBlock(d_model=hidden_dim, n_heads=n_heads, d_ff=hidden_dim * 4, dropout=0.1)
            for _ in range(n_layers)
        ])
        
        self.out_norm = nn.LayerNorm(hidden_dim)
        # 256 (Transformer) + 64 (StatBranch) = 320
        self.classifier = nn.Linear(hidden_dim + 64, num_classes)

    def forward(self, x, return_attention=False):
        # x: (B, 3, 35, 35)
        f_stat = self.stat_branch(x) # (B, 64)
        tokens = torch.cat([self.row_branch(x), self.seq_branch(x)], dim=-1) # (B, 35, 256)
        h = self.token_norm(self.token_proj(tokens) + self.pos_embed) # (B, 35, hidden_dim)
        
        attns = []
        for layer in self.layers:
            h, w = layer(h, need_weights=return_attention)
            if return_attention:
                attns.append(w)
                
        enc = self.out_norm(h) # (B, 35, hidden_dim)
        comb = torch.cat([enc, f_stat.unsqueeze(1).expand(-1, enc.size(1), -1)], dim=-1) # (B, 35, 320)
        
        logits_per_row = self.classifier(comb) # (B, 35, num_classes)
        # Top-K mean pooling along sequence dimension (dim=1)
        final_logits = torch.topk(logits_per_row, self.topk, dim=1).values.mean(dim=1) # (B, num_classes)
        
        if return_attention:
            # Average attention matrix across layers: shape (B, 35, 35)
            avg_attn = torch.stack(attns, dim=0).mean(dim=0)
            return final_logits, avg_attn
        return final_logits

if __name__ == "__main__":
    m = MEICViT(num_classes=15)
    m.eval()
    x = torch.randn(2, 3, 35, 35)
    logits, attn = m(x, return_attention=True)
    params = sum(p.numel() for p in m.parameters())
    print("Params (M):", params / 1e6)
    print("Logits shape:", logits.shape)
    print("Attention shape:", attn.shape)
    print("Self-test passed!")
