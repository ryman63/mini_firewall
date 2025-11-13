#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dmitriy");
MODULE_DESCRIPTION("Mini firewall LKM: blacklist IPv4 addresses via Netfilter and /dev interface");
MODULE_VERSION("1.0");

#define DEVICE_NAME "my_firewall"
#define CLASS_NAME  "myfw"
#define MAX_CMD_LEN 128
#define OUTPUT_BUF_SIZE 4096

struct blocked_ip {
    struct list_head list_node;
    __be32 ip;
};

static LIST_HEAD(blocked_ip_list);
static DEFINE_RWLOCK(ip_list_lock);

/* Netfilter hook ops */
static struct nf_hook_ops my_nfho;

/* char device */
static dev_t devt;
static struct cdev my_cdev;
static struct class* myclass;

/* helper: check if ip exists (caller must hold read or write lock) */
static struct blocked_ip* find_blocked_ip(__be32 ip)
{
    struct blocked_ip* ent;
    list_for_each_entry(ent, &blocked_ip_list, list_node) {
        if (ent->ip == ip)
            return ent;
    }
    return NULL;
}

/* Netfilter hook function */
static unsigned int my_firewall_hook_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
    struct iphdr* ip_header;
    __be32 src_ip;
    struct blocked_ip* ent;

    if (!skb)
        return NF_ACCEPT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    if (ip_header->version != 4)
        return NF_ACCEPT;

    src_ip = ip_header->saddr;

    read_lock(&ip_list_lock);
    ent = find_blocked_ip(src_ip);
    if (ent) {
        read_unlock(&ip_list_lock);
        pr_debug("mini_firewall: dropping packet from %pI4\n", &src_ip);
        return NF_DROP;
    }
    read_unlock(&ip_list_lock);

    return NF_ACCEPT;
}

struct myfw_filedata {
    char* outbuf;
    size_t outlen;
    size_t offset;
};

static int myfw_open(struct inode* inode, struct file* filp)
{
    struct myfw_filedata* fd;
    fd = kzalloc(sizeof(*fd), GFP_KERNEL);
    if (!fd)
        return -ENOMEM;
    fd->outbuf = NULL;
    fd->outlen = 0;
    fd->offset = 0;
    filp->private_data = fd;
    return 0;
}

static int myfw_release(struct inode* inode, struct file* filp)
{
    struct myfw_filedata* fd = filp->private_data;
    if (!fd)
        return 0;
    if (fd->outbuf)
        kfree(fd->outbuf);
    kfree(fd);
    filp->private_data = NULL;
    return 0;
}

static ssize_t myfw_read(struct file* filp, char __user* buf, size_t count, loff_t* ppos)
{
    struct myfw_filedata* fd = filp->private_data;
    size_t to_copy;

    if (!fd)
        return -EFAULT;

    if (!fd->outbuf) {
        struct blocked_ip* ent;
        char* b;
        size_t pos = 0;

        b = kzalloc(OUTPUT_BUF_SIZE, GFP_KERNEL);
        if (!b)
            return -ENOMEM;

        read_lock(&ip_list_lock);
        list_for_each_entry(ent, &blocked_ip_list, list_node) {
            int written = snprintf(b + pos, OUTPUT_BUF_SIZE - pos, "%pI4\n", &ent->ip);
            if (written < 0)
                break;
            pos += written;
            if (pos >= OUTPUT_BUF_SIZE - 64)
                break;
        }
        read_unlock(&ip_list_lock);

        fd->outbuf = b;
        fd->outlen = pos;
        fd->offset = 0;
    }

    if (fd->offset >= fd->outlen)
        return 0;

    to_copy = min(count, fd->outlen - fd->offset);
    if (copy_to_user(buf, fd->outbuf + fd->offset, to_copy))
        return -EFAULT;

    fd->offset += to_copy;
    return to_copy;
}

static int parse_ipv4_to_be32(const char* s, __be32* out)
{
    if (!s || !out)
        return -EINVAL;

    if (!in4_pton(s, -1, (u8*)out, -1, NULL))
        return -EINVAL;

    return 0;
}

static ssize_t myfw_write(struct file* filp, const char __user* buf, size_t count, loff_t* ppos)
{
    char kbuf[MAX_CMD_LEN];
    char cmd[8];
    char ipstr[40];
    __be32 ip_be;
    int res;

    if (count == 0 || count >= MAX_CMD_LEN)
        return -EINVAL;

    if (copy_from_user(kbuf, buf, count))
        return -EFAULT;
    kbuf[count] = '\0';

    if (kbuf[count - 1] == '\n')
        kbuf[count - 1] = '\0';

    res = sscanf(kbuf, "%7s %39s", cmd, ipstr);
    if (res != 2) {
        pr_info("mini_firewall: invalid command format\n");
        return -EINVAL;
    }

    if (parse_ipv4_to_be32(ipstr, &ip_be) != 0) {
        pr_info("mini_firewall: invalid IPv4 address: %s\n", ipstr);
        return -EINVAL;
    }

    if (strcmp(cmd, "add") == 0) {
        struct blocked_ip* ent;

        write_lock(&ip_list_lock);
        if (find_blocked_ip(ip_be)) {
            write_unlock(&ip_list_lock);
            pr_info("mini_firewall: ip %pI4 already blocked\n", &ip_be);
            return count;
        }

        ent = kmalloc(sizeof(*ent), GFP_KERNEL);
        if (!ent) {
            write_unlock(&ip_list_lock);
            return -ENOMEM;
        }
        INIT_LIST_HEAD(&ent->list_node);
        ent->ip = ip_be;
        list_add_tail(&ent->list_node, &blocked_ip_list);
        write_unlock(&ip_list_lock);
        pr_info("mini_firewall: added %pI4 to blacklist\n", &ip_be);
        return count;
    }
    else if (strcmp(cmd, "del") == 0) {
        struct blocked_ip* ent;
        int found = 0;

        write_lock(&ip_list_lock);
        list_for_each_entry(ent, &blocked_ip_list, list_node) {
            if (ent->ip == ip_be) {
                list_del(&ent->list_node);
                kfree(ent);
                found = 1;
                break;
            }
        }
        write_unlock(&ip_list_lock);

        if (found) {
            pr_info("mini_firewall: removed %pI4 from blacklist\n", &ip_be);
            return count;
        }
        else {
            pr_info("mini_firewall: ip %pI4 not found in blacklist\n", &ip_be);
            return -ENOENT;
        }
    }
    else {
        pr_info("mini_firewall: unknown command '%s'\n", cmd);
        return -EINVAL;
    }
}

static const struct file_operations myfw_fops = {
    .owner = THIS_MODULE,
    .open = myfw_open,
    .release = myfw_release,
    .read = myfw_read,
    .write = myfw_write,
};

static int __init myfw_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&devt, 0, 1, DEVICE_NAME);
    if (ret) {
        pr_err("mini_firewall: failed to alloc chrdev region: %d\n", ret);
        return ret;
    }

    cdev_init(&my_cdev, &myfw_fops);
    my_cdev.owner = THIS_MODULE;

    ret = cdev_add(&my_cdev, devt, 1);
    if (ret) {
        pr_err("mini_firewall: cdev_add failed: %d\n", ret);
        unregister_chrdev_region(devt, 1);
        return ret;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
    myclass = class_create(CLASS_NAME);
#else
    myclass = class_create(THIS_MODULE, CLASS_NAME);
#endif
    if (IS_ERR(myclass)) {
        pr_err("mini_firewall: class_create failed\n");
        cdev_del(&my_cdev);
        unregister_chrdev_region(devt, 1);
        return PTR_ERR(myclass);
    }

    if (IS_ERR(device_create(myclass, NULL, devt, NULL, DEVICE_NAME))) {
        pr_err("mini_firewall: device_create failed\n");
        class_destroy(myclass);
        cdev_del(&my_cdev);
        unregister_chrdev_region(devt, 1);
        return -EINVAL;
    }

    memset(&my_nfho, 0, sizeof(my_nfho));
    my_nfho.hook = my_firewall_hook_func;
    my_nfho.pf = PF_INET;
    my_nfho.hooknum = NF_INET_PRE_ROUTING;
    my_nfho.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &my_nfho);
    if (ret) {
        pr_err("mini_firewall: nf_register_net_hook failed: %d\n", ret);
        device_destroy(myclass, devt);
        class_destroy(myclass);
        cdev_del(&my_cdev);
        unregister_chrdev_region(devt, 1);
        return ret;
    }

    pr_info("mini_firewall: loaded, device /dev/%s major=%d minor=%d\n", DEVICE_NAME, MAJOR(devt), MINOR(devt));
    return 0;
}

static void __exit myfw_exit(void)
{
    struct blocked_ip* ent, * tmp;

    nf_unregister_net_hook(&init_net, &my_nfho);

    write_lock(&ip_list_lock);
    list_for_each_entry_safe(ent, tmp, &blocked_ip_list, list_node) {
        list_del(&ent->list_node);
        kfree(ent);
    }
    write_unlock(&ip_list_lock);

    device_destroy(myclass, devt);
    class_destroy(myclass);
    cdev_del(&my_cdev);
    unregister_chrdev_region(devt, 1);

    pr_info("mini_firewall: unloaded\n");
}

module_init(myfw_init);
module_exit(myfw_exit);